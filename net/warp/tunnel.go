// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package warp

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"sync"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/quic-go/quic-go/quicvarint"
	"tailscale.com/types/logger"
)

const (
	// l4ConnectSNI is the SNI used for the plain HTTP/3 CONNECT proxying
	// endpoint. Its certificate is pinned to the key returned during
	// registration, so the SNI itself need not match the edge's DNS name.
	l4ConnectSNI = "consumer-masque-proxy.cloudflareclient.com"

	// Cloudflare's consumer WARP edge uses a non-standard variant of
	// CONNECT-IP. The request is an Extended CONNECT to this authority with
	// :protocol=cf-connect-ip; the resulting HTTP datagrams carry complete IP
	// packets with Context ID zero.
	cfConnectIPProtocol  = "cf-connect-ip"
	cfConnectIPAuthority = "cloudflareaccess.com"

	defaultPort = 443
)

// Tunnel is a lazily-(re)established HTTP/3 connection to the WARP edge.
// A single QUIC connection carries one Cloudflare CONNECT-IP packet tunnel
// and may also carry plain CONNECT streams for TCP. If the connection dies it
// is transparently re-dialed on the next use.
type Tunnel struct {
	logf    logger.Logf
	cfg     *Config
	tls     *tls.Config
	quic    *quic.Config
	maddr   *net.UDPAddr // edge endpoint
	useIPv6 bool

	mu     sync.Mutex
	hconn  *http3.ClientConn // nil when disconnected
	packet *packetTunnel     // nil when CONNECT-IP is not established
	closed bool

	// prevQTransport tracks the prior (now closed) QUIC transport so it
	// can be cleaned up when a reconnect occurs. Without this, each
	// reconnect leaks a UDP socket.
	prevQTransport *quic.Transport
}

// packetTunnel is one accepted cf-connect-ip request stream. HTTP datagrams
// on the stream contain a QUIC-varint Context ID followed by an IP packet.
type packetTunnel struct {
	str        *http3.RequestStream
	resp       *http.Response
	readCtx    context.Context
	cancelRead context.CancelFunc
	closeOnce  sync.Once
}

// NewTunnel builds a Tunnel from a registration config. It performs no
// network I/O; Start or the first Dial establishes the QUIC connection.
func NewTunnel(logf logger.Logf, cfg *Config, useIPv6 bool) (*Tunnel, error) {
	if logf == nil {
		logf = logger.Discard
	}
	priv, err := cfg.ecPrivateKey()
	if err != nil {
		return nil, err
	}
	peer, err := cfg.ecEndpointPublicKey()
	if err != nil {
		return nil, err
	}
	certDER, err := genSelfSignedCert(&priv.PublicKey, priv)
	if err != nil {
		return nil, err
	}

	endpointIP := cfg.EndpointV4
	if useIPv6 {
		endpointIP = cfg.EndpointV6
	}
	if endpointIP == "" {
		return nil, fmt.Errorf("warp: no edge endpoint in config")
	}
	ip := net.ParseIP(endpointIP)
	if ip == nil {
		return nil, fmt.Errorf("warp: invalid edge endpoint %q", endpointIP)
	}
	port := cfg.EndpointPort
	if port == 0 {
		port = defaultPort
	}
	maddr := &net.UDPAddr{IP: ip, Port: port}

	tlsCfg := prepareTLSConfig(priv, peer, certDER)
	quicCfg := &quic.Config{
		EnableDatagrams:                true,
		KeepAlivePeriod:                30 * time.Second,
		InitialConnectionReceiveWindow: 10_000_000,
		MaxConnectionReceiveWindow:     10_000_000,
		InitialStreamReceiveWindow:     1_000_000,
		MaxStreamReceiveWindow:         1_000_000,
		MaxIncomingStreams:             100,
		MaxIncomingUniStreams:          100,
	}
	return &Tunnel{
		logf:    logger.WithPrefix(logf, "warp: "),
		cfg:     cfg,
		tls:     tlsCfg,
		quic:    quicCfg,
		maddr:   maddr,
		useIPv6: useIPv6,
	}, nil
}

// Endpoint returns the edge endpoint the tunnel dials, "ip:port".
func (t *Tunnel) Endpoint() string { return t.maddr.String() }

// EndpointIP returns the edge endpoint IP address.
func (t *Tunnel) EndpointIP() string { return t.maddr.IP.String() }

// isConnDead reports whether the HTTP/3 client connection has been torn
// down (i.e. its underlying QUIC context is done). It is used to guard
// t.drop() so a transient stream error on one goroutine doesn't nuke the
// shared connection for all concurrent dialers.
func isConnDead(hconn *http3.ClientConn) bool {
	select {
	case <-hconn.Context().Done():
		return true
	default:
		return false
	}
}

// ensureConnected returns a usable http3.ClientConn, dialing (or re-dialing)
// if needed. It must not be called with t.mu held.
func (t *Tunnel) ensureConnected(ctx context.Context) (*http3.ClientConn, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed {
		return nil, errors.New("warp: tunnel closed")
	}
	if t.hconn != nil {
		// Quick liveness check without blocking.
		select {
		case <-t.hconn.Context().Done():
			if t.packet != nil {
				_ = t.packet.Close()
				t.packet = nil
			}
			t.hconn = nil
			if t.prevQTransport != nil {
				_ = t.prevQTransport.Close()
				t.prevQTransport = nil
			}
		default:
			return t.hconn, nil
		}
	}

	t.logf("dialing WARP edge %s", t.maddr)
	udpConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
	if err != nil {
		return nil, err
	}

	// Set the SO_MARK bypass so WARP's own QUIC traffic isn't routed
	// through the TUN and intercepted by netstack's WARP hook (which
	// would create a routing loop). This is best-effort; on platforms
	// that don't support SO_MARK (or if we don't have permission) we
	// still continue — on those platforms there is no policy-routing
	// table 52 to bypass.
	if err := setListenSocketBypassMark(udpConn); err != nil {
		t.logf("failed to set bypass mark on UDP socket: %v", err)
	}
	// ConnectionIDLength must be 20 or the edge occasionally sends
	// PROTOCOL_VIOLATION and drops the connection (matches the official client).
	qtr := &quic.Transport{Conn: udpConn, ConnectionIDLength: 20}
	conn, err := qtr.Dial(ctx, t.maddr, t.tls, t.quic)
	if err != nil {
		udpConn.Close()
		return nil, fmt.Errorf("warp: QUIC dial failed: %w", err)
	}

	hconn := (&http3.Transport{DisableCompression: true}).NewClientConn(conn)

	// Wait until the server's SETTINGS are in so HEADERS can be sent safely.
	select {
	case <-hconn.ReceivedSettings():
	case <-ctx.Done():
		udpConn.Close()
		return nil, ctx.Err()
	}

	t.prevQTransport = qtr
	t.hconn = hconn
	t.logf("WARP tunnel established to %s", t.maddr)
	return hconn, nil
}

// Dial opens a plain HTTP/3 CONNECT stream (RFC 9114 §4.4) to address and
// returns a bidirectional net.Conn tunnel. network must be "tcp", "tcp4"
// or "tcp6"; address is a host:port or ip:port string. Hostnames are
// resolved locally so the edge receives an IP in :authority.
func (t *Tunnel) Dial(ctx context.Context, network, address string) (net.Conn, error) {
	if network != "tcp" && network != "tcp4" && network != "tcp6" {
		return nil, fmt.Errorf("warp: unsupported network %q", network)
	}
	authority := ensurePort(address)
	// Resolve hostnames locally (the reference clients do this by default)
	// so the edge receives an IP address in :authority.
	if h, p, err := net.SplitHostPort(authority); err == nil && net.ParseIP(h) == nil {
		ips, err := net.LookupIP(h)
		if err != nil || len(ips) == 0 {
			return nil, fmt.Errorf("warp: resolve %s: %w", h, err)
		}
		authority = net.JoinHostPort(ips[0].String(), p)
	}

	var lastErr error
	// A few attempts, re-dialing if the QUIC connection is dead or the
	// first handshake hits a transient network timeout.
	for attempt := 0; attempt < 3; attempt++ {
		hconn, err := t.ensureConnected(ctx)
		if err != nil {
			lastErr = err
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			time.Sleep(time.Duration(attempt+1) * 300 * time.Millisecond)
			continue
		}
		str, err := hconn.OpenRequestStream(ctx)
		if err != nil {
			// Only drop the connection if it's actually dead;
			// otherwise a transient stream error on one goroutine
			// would nuke the shared connection for all concurrent
			// dialers (surfacing as "Application error 0x0 (local)").
			if isConnDead(hconn) {
				t.drop()
			}
			lastErr = err
			continue
		}
		req, err := http.NewRequest(http.MethodConnect, "https://"+authority, nil)
		if err != nil {
			return nil, err
		}
		// Default Proto is HTTP/1.1 => plain CONNECT (no :scheme/:path/:protocol).
		req.Host = authority
		if err := str.SendRequestHeader(req); err != nil {
			str.CancelWrite(quic.StreamErrorCode(0))
			lastErr = err
			continue
		}
		resp, err := str.ReadResponse()
		if err != nil {
			str.CancelWrite(quic.StreamErrorCode(0))
			lastErr = err
			continue
		}
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			resp.Body.Close()
			str.Close()
			return nil, fmt.Errorf("warp: edge CONNECT to %s refused: %s", authority, resp.Status)
		}
		return &tunnelConn{str: str, resp: resp, authority: authority}, nil
	}
	if lastErr == nil {
		lastErr = errors.New("unknown")
	}
	return nil, fmt.Errorf("warp: dial %s failed: %w", authority, lastErr)
}

// ensurePacketConnected establishes Cloudflare's CONNECT-IP request stream.
// Cloudflare's consumer edge predates the final RFC 9484 protocol token and
// uses "cf-connect-ip". It also does not advertise Extended CONNECT in its
// HTTP/3 settings, so only H3 datagram support can be checked before sending
// the request.
func (t *Tunnel) ensurePacketConnected(ctx context.Context) (*packetTunnel, error) {
	hconn, err := t.ensureConnected(ctx)
	if err != nil {
		return nil, err
	}

	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed {
		return nil, errors.New("warp: tunnel closed")
	}
	if t.packet != nil {
		select {
		case <-t.packet.readCtx.Done():
			_ = t.packet.Close()
			t.packet = nil
		default:
			return t.packet, nil
		}
	}
	if hconn != t.hconn || isConnDead(hconn) {
		return nil, errors.New("warp: HTTP/3 connection closed before CONNECT-IP")
	}
	if !hconn.Settings().EnableDatagrams {
		return nil, errors.New("warp: edge did not enable HTTP/3 datagrams")
	}

	str, err := hconn.OpenRequestStream(ctx)
	if err != nil {
		return nil, fmt.Errorf("warp: open CONNECT-IP stream: %w", err)
	}
	req := &http.Request{
		Method: http.MethodConnect,
		Proto:  cfConnectIPProtocol,
		Host:   cfConnectIPAuthority,
		Header: http.Header{
			http3.CapsuleProtocolHeader: []string{"?1"},
			"User-Agent":                []string{"tailscale-warp"},
		},
		URL: &url.URL{Scheme: "https", Host: cfConnectIPAuthority},
	}
	if err := str.SendRequestHeader(req); err != nil {
		str.CancelWrite(quic.StreamErrorCode(0))
		return nil, fmt.Errorf("warp: send CONNECT-IP request: %w", err)
	}
	resp, err := str.ReadResponse()
	if err != nil {
		str.CancelWrite(quic.StreamErrorCode(0))
		return nil, fmt.Errorf("warp: read CONNECT-IP response: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		resp.Body.Close()
		str.Close()
		return nil, fmt.Errorf("warp: edge CONNECT-IP refused: %s", resp.Status)
	}
	pc := newPacketTunnel(str, resp)
	t.packet = pc
	t.logf("CONNECT-IP packet tunnel established")
	return pc, nil
}

func newPacketTunnel(str *http3.RequestStream, resp *http.Response) *packetTunnel {
	pc := &packetTunnel{str: str, resp: resp}
	pc.readCtx, pc.cancelRead = context.WithCancel(context.Background())
	// CONNECT-IP capsules share the request stream with datagrams. The
	// registration already supplies the assigned addresses, so no capsule is
	// currently actionable, but the stream still needs to be drained to avoid
	// flow-control stalls and to notice a remotely closed request.
	go func() {
		_, _ = io.Copy(io.Discard, resp.Body)
		pc.cancelRead()
	}()
	return pc
}

// SendPacket sends one complete IPv4 or IPv6 packet through CONNECT-IP.
func (t *Tunnel) SendPacket(packet []byte) error {
	t.mu.Lock()
	pc := t.packet
	t.mu.Unlock()
	if pc == nil {
		return errors.New("warp: CONNECT-IP packet tunnel is not connected")
	}
	if err := pc.SendPacket(packet); err != nil {
		return fmt.Errorf("warp: send IP packet: %w", err)
	}
	return nil
}

// invalidatePacket removes pc if it is the active CONNECT-IP stream.
func (t *Tunnel) invalidatePacket(pc *packetTunnel) {
	t.mu.Lock()
	if t.packet == pc {
		t.packet = nil
	}
	t.mu.Unlock()
	pc.Close()
}

func (pc *packetTunnel) SendPacket(packet []byte) error {
	packet, err := prepareIPPacket(packet)
	if err != nil {
		return err
	}
	// Context ID zero is the single-byte QUIC varint 0x00. quic-go adds
	// the HTTP/3 quarter-stream ID around this payload.
	dg := make([]byte, 1+len(packet))
	copy(dg[1:], packet)
	return pc.str.SendDatagram(dg)
}

func (pc *packetTunnel) ReadPacket() ([]byte, error) {
	for {
		dg, err := pc.str.ReceiveDatagram(pc.readCtx)
		if err != nil {
			return nil, err
		}
		contextID, n, err := quicvarint.Parse(dg)
		if err != nil {
			return nil, fmt.Errorf("warp: malformed CONNECT-IP datagram: %w", err)
		}
		if contextID != 0 {
			continue
		}
		packet, err := validIPPacket(dg[n:])
		if err != nil {
			continue
		}
		return append([]byte(nil), packet...), nil
	}
}

func (pc *packetTunnel) Close() error {
	pc.closeOnce.Do(func() {
		pc.cancelRead()
		pc.str.CancelRead(quic.StreamErrorCode(http3.ErrCodeNoError))
		_ = pc.str.Close()
		_ = pc.resp.Body.Close()
	})
	return nil
}

// prepareIPPacket validates an inner packet and applies the router hop-count
// decrement required by CONNECT-IP. The caller owns packet and permits it to
// be modified in place.
func prepareIPPacket(packet []byte) ([]byte, error) {
	packet, err := validIPPacket(packet)
	if err != nil {
		return nil, err
	}
	switch packet[0] >> 4 {
	case 4:
		if packet[8] <= 1 {
			return nil, errors.New("warp: IPv4 packet TTL exhausted")
		}
		packet[8]--
		hlen := int(packet[0]&0x0f) * 4
		packet[10], packet[11] = 0, 0
		binary.BigEndian.PutUint16(packet[10:12], internetChecksum(packet[:hlen]))
	case 6:
		if packet[7] <= 1 {
			return nil, errors.New("warp: IPv6 packet hop limit exhausted")
		}
		packet[7]--
	}
	return packet, nil
}

// validIPPacket validates and trims packet to the length encoded in its IP
// header. CONNECT-IP datagrams contain exactly one complete IP packet.
func validIPPacket(packet []byte) ([]byte, error) {
	if len(packet) == 0 {
		return nil, errors.New("warp: empty IP packet")
	}
	switch packet[0] >> 4 {
	case 4:
		if len(packet) < 20 {
			return nil, errors.New("warp: short IPv4 packet")
		}
		hlen := int(packet[0]&0x0f) * 4
		total := int(binary.BigEndian.Uint16(packet[2:4]))
		if hlen < 20 || total < hlen || total > len(packet) {
			return nil, errors.New("warp: malformed IPv4 packet length")
		}
		return packet[:total], nil
	case 6:
		if len(packet) < 40 {
			return nil, errors.New("warp: short IPv6 packet")
		}
		total := 40 + int(binary.BigEndian.Uint16(packet[4:6]))
		if total > len(packet) {
			return nil, errors.New("warp: malformed IPv6 packet length")
		}
		return packet[:total], nil
	default:
		return nil, errors.New("warp: unsupported IP version")
	}
}

func internetChecksum(b []byte) uint16 {
	var sum uint32
	for len(b) >= 2 {
		sum += uint32(binary.BigEndian.Uint16(b[:2]))
		b = b[2:]
	}
	if len(b) == 1 {
		sum += uint32(b[0]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

// drop invalidates the current connection so the next Dial re-establishes it.
func (t *Tunnel) drop() {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.packet != nil {
		_ = t.packet.Close()
		t.packet = nil
	}
	if t.hconn != nil {
		_ = t.hconn.CloseWithError(quic.ApplicationErrorCode(0), "")
		t.hconn = nil
	}
	// Close the previous transport + UDP socket to avoid leaking fds
	// on reconnect.
	if t.prevQTransport != nil {
		_ = t.prevQTransport.Close()
		t.prevQTransport = nil
	}
}

// Close closes the tunnel and all sessions on it.
func (t *Tunnel) Close() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.closed = true
	if t.packet != nil {
		_ = t.packet.Close()
		t.packet = nil
	}
	if t.hconn != nil {
		_ = t.hconn.CloseWithError(quic.ApplicationErrorCode(0), "")
		t.hconn = nil
	}
	if t.prevQTransport != nil {
		_ = t.prevQTransport.Close()
		t.prevQTransport = nil
	}
	return nil
}

// tunnelConn adapts an HTTP/3 CONNECT RequestStream to a net.Conn.
type tunnelConn struct {
	str       *http3.RequestStream
	resp      *http.Response
	authority string
}

func (c *tunnelConn) Read(p []byte) (int, error)  { return c.resp.Body.Read(p) }
func (c *tunnelConn) Write(p []byte) (int, error) { return c.str.Write(p) }
func (c *tunnelConn) Close() error                { _ = c.str.Close(); return c.resp.Body.Close() }
func (c *tunnelConn) LocalAddr() net.Addr         { return nil }
func (c *tunnelConn) RemoteAddr() net.Addr        { return nil }
func (c *tunnelConn) SetDeadline(time.Time) error { return nil }
func (c *tunnelConn) SetReadDeadline(time.Time) error {
	return nil
}
func (c *tunnelConn) SetWriteDeadline(time.Time) error { return nil }

// Relays bytes between two Conns until either side closes.
func relay(a, b net.Conn) {
	done := make(chan struct{}, 2)
	go func() { defer func() { done <- struct{}{} }(); _, _ = io.Copy(b, a) }()
	go func() { defer func() { done <- struct{}{} }(); _, _ = io.Copy(a, b) }()
	<-done
	_ = a.Close()
	_ = b.Close()
}

// ensurePort appends :443 (the default target port) if address has no port.
func ensurePort(addr string) string {
	if _, _, err := net.SplitHostPort(addr); err == nil {
		return addr
	}
	return net.JoinHostPort(addr, strconv.Itoa(defaultPort))
}

// prepareTLSConfig builds the mTLS client config: a self-signed cert signed
// by the enrolled P-256 key, ALPN=h3, and edge certificate pinning.
func prepareTLSConfig(priv *ecdsa.PrivateKey, peer *ecdsa.PublicKey, cert [][]byte) *tls.Config {
	return &tls.Config{
		Certificates: []tls.Certificate{{Certificate: cert, PrivateKey: priv}},
		ServerName:   l4ConnectSNI,
		NextProtos:   []string{http3.NextProtoH3},
		// The SNI is not the endpoint's real name; we pin instead.
		InsecureSkipVerify: true,
		VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			if len(rawCerts) == 0 {
				return nil
			}
			crt, err := x509.ParseCertificate(rawCerts[0])
			if err != nil {
				return err
			}
			pk, ok := crt.PublicKey.(*ecdsa.PublicKey)
			if !ok {
				return x509.ErrUnsupportedAlgorithm
			}
			if !pk.Equal(peer) {
				return fmt.Errorf("warp: edge certificate public key does not match pinned key")
			}
			return nil
		},
	}
}

// genSelfSignedCert creates a self-signed cert bound to the enrolled P-256 key.
func genSelfSignedCert(pub, priv any) ([][]byte, error) {
	der, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{
		SerialNumber: big.NewInt(0),
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}, &x509.Certificate{}, pub, priv)
	if err != nil {
		return nil, err
	}
	return [][]byte{der}, nil
}
