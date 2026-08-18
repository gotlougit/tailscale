// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package warp

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/quic-go/qpack"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/quic-go/quic-go/quicvarint"
	"tailscale.com/net/packet"
	"tailscale.com/types/logger"
)

// fakeAPI implements the Cloudflare WARP registration API in-process.
type fakeAPI struct {
	t        *testing.T
	ts       *httptest.Server
	edgeIP   string // "127.0.0.1:<port>" reported to registrants
	edgePort int    // edge's QUIC port
	pubPEM   string // PEM of the edge's pinned public key

	posts  atomic.Int64 // count of POST /reg requests
	patche atomic.Int64 // count of PATCH /reg/{id} requests
}

func newFakeAPI(t *testing.T, edgeIP, pubPEM string) *fakeAPI {
	a := &fakeAPI{t: t, edgeIP: edgeIP, pubPEM: pubPEM}
	_, portStr, err := net.SplitHostPort(edgeIP)
	if err != nil {
		t.Fatalf("bad edgeIP %q: %v", edgeIP, err)
	}
	port, err := strconv.ParseInt(portStr, 10, 32)
	if err != nil {
		t.Fatalf("bad edge port %q: %v", portStr, err)
	}
	a.edgePort = int(port)
	a.ts = httptest.NewServer(http.HandlerFunc(a.handle))
	t.Cleanup(a.ts.Close)
	return a
}

func (a *fakeAPI) url() string { return a.ts.URL }

func (a *fakeAPI) handle(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("CF-Client-Version") == "" {
		http.Error(w, "missing CF-Client-Version", http.StatusBadRequest)
		return
	}
	switch {
	case r.Method == http.MethodPost && r.URL.Path == "/"+apiVersion()+"/reg":
		a.posts.Add(1)
		var req map[string]any
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "bad body", http.StatusBadRequest)
			return
		}
		if req["key"] == "" || req["tos"] == "" {
			http.Error(w, "missing key/tos", http.StatusBadRequest)
			return
		}
		if req["tunnel_type"] != wgTunType || req["key_type"] != wgKeyType {
			http.Error(w, "wrong tun/key type", http.StatusBadRequest)
			return
		}
		json.NewEncoder(w).Encode(map[string]any{"id": "test-account-id", "token": "test-token", "config": map[string]any{}})
	case r.Method == http.MethodPatch && r.URL.Path == "/"+apiVersion()+"/reg/test-account-id":
		a.patche.Add(1)
		if r.Header.Get("Authorization") != "Bearer test-token" {
			http.Error(w, "bad auth", http.StatusUnauthorized)
			return
		}
		var req map[string]any
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "bad body", http.StatusBadRequest)
			return
		}
		if req["tunnel_type"] != mqTunType || req["key_type"] != mqKeyType {
			http.Error(w, "wrong tun/key type", http.StatusBadRequest)
			return
		}
		json.NewEncoder(w).Encode(map[string]any{
			"id":    "test-account-id",
			"token": "test-token",
			"config": map[string]any{
				"peers": []map[string]any{{
					"public_key": a.pubPEM,
					"endpoint": map[string]any{
						"v4":    a.edgeIP,
						"v6":    "",
						"host":  "",
						"ports": []int{a.edgePort},
					},
				}},
				"interface": map[string]any{
					"addresses": map[string]any{"v4": "100.96.0.1", "v6": "fd01::1"},
				},
			},
		})
	default:
		http.Error(w, "not found", http.StatusNotFound)
	}
}

// fakeEdge is an in-process stand-in for Cloudflare's MASQUE edge: a raw
// QUIC HTTP/3 server speaking plain CONNECT and Cloudflare's cf-connect-ip
// protocol, with the edge TLS certificate pinned by the client.
type fakeEdge struct {
	t       *testing.T
	udpConn *net.UDPConn
	tr      *quic.Transport
	ln      *quic.Listener
	priv    *ecdsa.PrivateKey

	tcpStreams    atomic.Int64 // CONNECT sessions served
	packetTunnels atomic.Int64 // cf-connect-ip sessions served
}

func newFakeEdge(t *testing.T) *fakeEdge {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	udpConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	fe := &fakeEdge{t: t, udpConn: udpConn, priv: priv}
	tr := &quic.Transport{Conn: udpConn, ConnectionIDLength: 20}
	ln, err := tr.Listen(edgeTLSConfig(priv), &quic.Config{
		EnableDatagrams: true,
		KeepAlivePeriod: 5 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	fe.tr, fe.ln = tr, ln
	t.Cleanup(func() { ln.Close(); tr.Close(); udpConn.Close() })
	go fe.acceptLoop()
	return fe
}

// pubPEM returns the edge's pinned public key in PEM form, as included in
// registration responses.
func (e *fakeEdge) pubPEM() string {
	pubDER, err := x509.MarshalPKIXPublicKey(&e.priv.PublicKey)
	if err != nil {
		e.t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER}))
}

func (e *fakeEdge) addr() netip.AddrPort {
	return netip.MustParseAddrPort(e.udpConn.LocalAddr().String())
}

func (e *fakeEdge) acceptLoop() {
	for {
		conn, err := e.ln.Accept(context.Background())
		if err != nil {
			e.t.Logf("fakeEdge accept: %v", err)
			return
		}
		go e.serveConn(conn)
	}
}

// serveConn serves one QUIC connection: it sends its SETTINGS on a control
// stream, then handles request streams.
func (e *fakeEdge) serveConn(conn *quic.Conn) {
	// Control stream: stream-type 0 (control), SETTINGS frame with the
	// H3_DATAGRAM (0x33) and EXTENDED_CONNECT (0x08) settings.
	ctrl, err := conn.OpenUniStream()
	if err != nil {
		return
	}
	settings := []byte{0x00, 0x04, 0x04, 0x33, 0x01, 0x08, 0x01}
	if _, err := ctrl.Write(settings); err != nil {
		return
	}
	// The control stream must stay open for the connection's lifetime;
	// closing it is a critical-stream error at the peer.

	for {
		str, err := conn.AcceptStream(context.Background())
		if err != nil {
			return
		}
		go e.handleStream(conn, str)
	}
}

// handleStream parses one HTTP/3 request, responds 200, and then serves an
// echo session: byte-stream echo for plain CONNECT, datagram echo for
// cf-connect-ip.
func (e *fakeEdge) handleStream(conn *quic.Conn, str *quic.Stream) {
	br := bufio.NewReader(str)
	var method, authority, protocol, path, capsuleProtocol string
	for {
		ft, err := quicvarint.Read(br)
		if err != nil {
			str.CancelWrite(0)
			return
		}
		fl, err := quicvarint.Read(br)
		if err != nil {
			str.CancelWrite(0)
			return
		}
		if ft == 0x1 { // HEADERS
			block := make([]byte, fl)
			if _, err := io.ReadFull(br, block); err != nil {
				str.CancelWrite(0)
				return
			}
			df := qpack.NewDecoder().Decode(block)
			for {
				hf, err := df()
				if err == io.EOF {
					break
				}
				if err != nil {
					e.t.Logf("fakeEdge: qpack decode err: %v (block % x)", err, block)
					str.CancelWrite(0)
					return
				}
				switch hf.Name {
				case ":method":
					method = hf.Value
				case ":authority":
					authority = hf.Value
				case ":protocol":
					protocol = hf.Value
				case ":path":
					path = hf.Value
				case "capsule-protocol":
					capsuleProtocol = hf.Value
				}
			}
			break
		}
		if _, err := io.CopyN(io.Discard, br, int64(fl)); err != nil {
			str.CancelWrite(0)
			return
		}
	}

	if method != "CONNECT" || authority == "" {
		str.CancelWrite(quic.StreamErrorCode(0))
		return
	}
	// Respond 200. The QPACK header block is: required insert count 0,
	// delta base 0, then an indexed field line (1Txxxxxx, T=1 for the
	// static table) referencing static table entry 25 (":status: 200").
	hdr := quicvarint.Append(nil, 0x1) // HEADERS frame type
	hdr = quicvarint.Append(hdr, 3)    // frame length
	hdr = append(hdr, 0x00, 0x00, 0xc0|25)
	if _, err := str.Write(hdr); err != nil {
		str.CancelWrite(0)
		return
	}

	switch protocol {
	case cfConnectIPProtocol:
		if authority != cfConnectIPAuthority || path != "/" || capsuleProtocol != "?1" {
			e.t.Errorf("bad cf-connect-ip request: authority=%q path=%q capsule-protocol=%q", authority, path, capsuleProtocol)
			str.CancelWrite(0)
			return
		}
		e.packetTunnels.Add(1)
		e.servePacketEcho(conn)
	default: // plain CONNECT (TCP)
		e.tcpStreams.Add(1)
		// Echo relay: read raw bytes written by the client (br may have
		// buffered some) and write them back until EOF.
		io.Copy(str, br)
		io.Copy(io.Discard, str)
		str.Close()
	}
}

// servePacketEcho echoes HTTP datagrams, including their quarter-stream ID,
// Context ID zero, and complete inner IP packet.
func (e *fakeEdge) servePacketEcho(conn *quic.Conn) {
	for {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		dg, err := conn.ReceiveDatagram(ctx)
		cancel()
		if err != nil {
			e.t.Logf("fakeEdge: packet recv err: %v", err)
			return
		}
		if err := conn.SendDatagram(dg); err != nil {
			e.t.Logf("fakeEdge: packet echo err: %v", err)
			return
		}
	}
}

func edgeTLSConfig(priv *ecdsa.PrivateKey) *tls.Config {
	templ := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: l4ConnectSNI},
		DNSNames:     []string{l4ConnectSNI},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, templ, templ, &priv.PublicKey, priv)
	if err != nil {
		panic(err)
	}
	return &tls.Config{
		Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: priv}},
		NextProtos:   []string{http3.NextProtoH3},
	}
}

// newTestClient registers a fresh device against a fake API + edge and
// returns a started Client.
func newTestClient(t *testing.T) *Client {
	t.Helper()
	edge := newFakeEdge(t)
	api := newFakeAPI(t, edge.addr().String(), edge.pubPEM())

	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "warp-client.json")
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cfg, err := RegisterWithOptions(ctx, logger.Discard, RegisterOptions{BaseURL: api.url()})
	if err != nil {
		t.Fatalf("RegisterWithOptions: %v", err)
	}
	if err := cfg.Save(cfgPath); err != nil {
		t.Fatalf("save config: %v", err)
	}

	cl := NewClient(logger.Discard, cfgPath, false)
	t.Cleanup(func() { cl.Close() })
	if err := cl.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	return cl
}

func TestConfigRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "warp.json")
	cfg := &Config{
		PrivateKey:     "aGVsbG8=",
		EndpointV4:     "162.159.198.2",
		EndpointV6:     "",
		EndpointPort:   443,
		EndpointPubKey: "-----BEGIN PUBLIC KEY-----\nZm9v\n-----END PUBLIC KEY-----\n",
		ID:             "acct-1",
		AccessToken:    "tok",
		IPv4:           "100.96.0.1",
	}
	if !cfg.Valid() {
		t.Fatal("config should be valid")
	}
	if err := cfg.Save(path); err != nil {
		t.Fatal(err)
	}
	var got Config
	if err := got.Load(path); err != nil {
		t.Fatal(err)
	}
	if got.ID != cfg.ID || got.AccessToken != cfg.AccessToken || got.EndpointV4 != cfg.EndpointV4 {
		t.Fatalf("round trip mismatch: %+v != %+v", got, cfg)
	}

	// A config missing the pinned key is not valid.
	bad := *cfg
	bad.EndpointPubKey = ""
	if bad.Valid() {
		t.Fatal("config without pinned key should be invalid")
	}
}

func TestInterceptable(t *testing.T) {
	tests := []struct {
		ip   string
		want bool
	}{
		// Internet / public addresses: intercepted.
		{"1.1.1.1", true},
		{"8.8.8.8", true},
		{"93.184.216.34", true},
		{"2606:4700:4700::1111", true},
		{"2001:4860:4860::8888", true},

		// Tailnet / CGNAT: not intercepted.
		{"100.64.0.1", false},
		{"100.101.102.103", false},
		{"100.100.100.100", false}, // MagicDNS
		{"fd7a:115c:a1e0::1", false},
		{"fd7a:115c:a1e0:ab12::1", false},

		// Local networks.
		{"10.0.0.1", false},
		{"10.255.255.255", false},
		{"172.16.0.1", false},
		{"172.31.255.255", false},
		{"192.168.1.1", false},
		{"192.168.255.255", false},
		{"fd00::1", false}, // ULA

		// Localhost / link-local / multicast / special.
		{"127.0.0.1", false},
		{"127.255.255.255", false},
		{"::1", false},
		{"169.254.169.254", false}, // link-local
		{"fe80::1", false},
		{"224.0.0.1", false},
		{"ff02::1", false},
		{"0.0.0.0", false},
		{"255.255.255.255", false},
		{"::", false},
	}
	for _, tt := range tests {
		ip := netip.MustParseAddr(tt.ip)
		if got := Interceptable(ip); got != tt.want {
			t.Errorf("Interceptable(%v) = %v; want %v", tt.ip, got, tt.want)
		}
	}
}

func TestRegister(t *testing.T) {
	edge := newFakeEdge(t)
	api := newFakeAPI(t, edge.addr().String(), edge.pubPEM())

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cfg, err := RegisterWithOptions(ctx, logger.Discard, RegisterOptions{BaseURL: api.url()})
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	if api.posts.Load() != 1 || api.patche.Load() != 1 {
		t.Fatalf("expected 1 POST and 1 PATCH, got %d %d", api.posts.Load(), api.patche.Load())
	}
	if !cfg.Valid() {
		t.Fatal("registration result not valid")
	}
	if cfg.ID != "test-account-id" || cfg.AccessToken != "test-token" {
		t.Fatalf("unexpected identity: %+v", cfg)
	}
	if cfg.EndpointV4 != "127.0.0.1" {
		t.Fatalf("unexpected endpoint: %q", cfg.EndpointV4)
	}
	if cfg.IPv4 != "100.96.0.1" {
		t.Fatalf("unexpected assigned IPv4: %q", cfg.IPv4)
	}
	// The enrolled MASQUE private key must round-trip as an ECDSA P-256 key.
	priv, err := cfg.ecPrivateKey()
	if err != nil {
		t.Fatalf("ecPrivateKey: %v", err)
	}
	if !priv.Curve.IsOnCurve(priv.X, priv.Y) {
		t.Fatal("enrolled key not on curve")
	}
	pub, err := cfg.ecEndpointPublicKey()
	if err != nil {
		t.Fatalf("ecEndpointPublicKey: %v", err)
	}
	if !pub.Equal(&edge.priv.PublicKey) {
		t.Fatal("pinned edge key mismatch")
	}
}

// TestTunnelTCP verifies that TCP connections flow through the WARP tunnel:
// the data written by the client is received by the edge's CONNECT handler
// with the right :authority, and the edge's bytes are returned verbatim.
func TestTunnelTCP(t *testing.T) {
	cl := newTestClient(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	conn, err := cl.Dial(ctx, "tcp", "203.0.113.1:443")
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer conn.Close()
	msg := "ping through warp"
	if _, err := conn.Write([]byte(msg)); err != nil {
		t.Fatalf("Write: %v", err)
	}
	buf := make([]byte, len(msg))
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("ReadFull: %v", err)
	}
	if string(buf) != msg {
		t.Fatalf("got %q; want %q", buf, msg)
	}
	st := cl.Status()
	if !st.Connected {
		t.Fatalf("status: not connected: %+v", st)
	}
}

// TestTunnelPackets verifies that complete IP packets flow through the single
// cf-connect-ip tunnel and come back intact.
func TestTunnelPackets(t *testing.T) {
	cl := newTestClient(t)
	received := make(chan []byte, 1)
	cl.SetPacketHandler(func(p []byte) { received <- p })

	p := packet.Generate(packet.UDP4Header{
		IP4Header: packet.IP4Header{
			Src: netip.MustParseAddr("100.96.0.1"),
			Dst: netip.MustParseAddr("203.0.113.1"),
		},
		SrcPort: 4242,
		DstPort: 53,
	}, []byte("dns query bytes"))
	if err := cl.SendPacket(p); err != nil {
		t.Fatalf("SendPacket: %v", err)
	}

	select {
	case got := <-received:
		var parsed packet.Parsed
		parsed.Decode(got)
		if parsed.IPVersion != 4 || parsed.Src.Port() != 4242 || parsed.Dst.Port() != 53 {
			t.Fatalf("unexpected echoed packet: %v", &parsed)
		}
		if got[8] != 63 {
			t.Fatalf("echoed TTL = %d, want 63", got[8])
		}
		if string(parsed.Payload()) != "dns query bytes" {
			t.Fatalf("echoed payload = %q", parsed.Payload())
		}
	case <-time.After(10 * time.Second):
		t.Fatal("timed out waiting for echoed IP packet")
	}
}

func TestClientSendPacketRequiresStart(t *testing.T) {
	dir := t.TempDir()
	cl := NewClient(logger.Discard, filepath.Join(dir, "warp-client.json"), false)
	if err := cl.SendPacket(nil); err == nil {
		t.Fatal("expected error sending on unstarted client")
	}
}

// TestTunnelAutoReconnect verifies that the tunnel re-establishes both its
// QUIC connection and CONNECT-IP request after the edge connection drops.
func TestTunnelAutoReconnect(t *testing.T) {
	cl := newTestClient(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	packetReply := make(chan []byte, 1)
	cl.SetPacketHandler(func(p []byte) { packetReply <- p })

	checkEcho := func(want string) {
		t.Helper()
		conn, err := cl.Dial(ctx, "tcp", "203.0.113.2:80")
		if err != nil {
			t.Fatalf("Dial after reconnect: %v", err)
		}
		defer conn.Close()
		if _, err := conn.Write([]byte(want)); err != nil {
			t.Fatalf("Write: %v", err)
		}
		buf := make([]byte, len(want))
		if _, err := io.ReadFull(conn, buf); err != nil {
			t.Fatalf("ReadFull: %v", err)
		}
		if string(buf) != want {
			t.Fatalf("got %q; want %q", buf, want)
		}
	}

	checkEcho("first")
	cl.mu.Lock()
	if cl.tunnel == nil {
		cl.mu.Unlock()
		t.Fatal("no tunnel")
	}
	cl.tunnel.drop() // kill the QUIC connection underneath
	cl.mu.Unlock()
	checkEcho("second") // Dial must transparently re-establish

	for {
		p := packet.Generate(packet.UDP4Header{
			IP4Header: packet.IP4Header{
				Src: netip.MustParseAddr("100.96.0.1"),
				Dst: netip.MustParseAddr("203.0.113.1"),
			},
			SrcPort: 4242,
			DstPort: 53,
		}, []byte("after reconnect"))
		if err := cl.SendPacket(p); err == nil {
			break
		}
		select {
		case <-ctx.Done():
			t.Fatal("CONNECT-IP did not reconnect")
		case <-time.After(100 * time.Millisecond):
		}
	}
	select {
	case <-packetReply:
	case <-ctx.Done():
		t.Fatal("no packet reply after CONNECT-IP reconnect")
	}
}

// TestClientStatus verifies the status surface of an idle (unstarted) client.
func TestClientStatus(t *testing.T) {
	dir := t.TempDir()
	cl := NewClient(logger.Discard, filepath.Join(dir, "warp-client.json"), false)
	if st := cl.Status(); st.Registered {
		t.Fatalf("unregistered client reports registered: %+v", st)
	}
	if err := cl.Start(context.Background()); err == nil {
		t.Fatal("Start without registration should fail")
	} else if !strings.Contains(err.Error(), "no valid registration") {
		t.Fatalf("unexpected error: %v", err)
	}
}

// TestTunnelRejectsNonTCPNetworks ensures only TCP-ish networks are dialable.
func TestTunnelRejectsNonTCPNetworks(t *testing.T) {
	cl := newTestClient(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if _, err := cl.Dial(ctx, "udp", "1.1.1.1:53"); err == nil {
		t.Fatal("expected error dialing udp via Dial")
	}
}

// TestTunnelConcurrentPackets verifies that concurrent senders share the
// single CONNECT-IP packet tunnel without losing datagrams.
func TestTunnelConcurrentPackets(t *testing.T) {
	cl := newTestClient(t)
	const n = 5
	received := make(chan []byte, n)
	cl.SetPacketHandler(func(p []byte) { received <- p })
	errs := make(chan error, n)
	for i := range n {
		go func(i int) {
			p := packet.Generate(packet.UDP4Header{
				IP4Header: packet.IP4Header{
					Src: netip.MustParseAddr("100.96.0.1"),
					Dst: netip.MustParseAddr("203.0.113.1"),
				},
				SrcPort: uint16(4200 + i),
				DstPort: 53,
			}, []byte("hello"))
			errs <- cl.SendPacket(p)
		}(i)
	}
	for range n {
		if err := <-errs; err != nil {
			t.Fatalf("SendPacket: %v", err)
		}
	}
	seen := make(map[uint16]bool)
	for range n {
		select {
		case raw := <-received:
			var p packet.Parsed
			p.Decode(raw)
			seen[p.Src.Port()] = true
		case <-time.After(10 * time.Second):
			t.Fatal("timed out waiting for echoed packet")
		}
	}
	if len(seen) != n {
		t.Errorf("received %d/%d distinct packet flows", len(seen), n)
	}
}
