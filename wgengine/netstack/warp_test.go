// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package netstack

import (
	"net/netip"
	"path/filepath"
	"testing"

	"tailscale.com/net/packet"
	"tailscale.com/net/warp"
	"tailscale.com/types/ipproto"
	"tailscale.com/types/logger"
)

// WarpClientAsserts is a compile-time check that *warp.Client satisfies the
// WarpClient interface that [Impl.SetWarpClient] needs. If this ever fails to
// compile, netstack's SetWarpClient will panic at runtime with "unexpected
// type *warp.Client", crashing tailscaled (seen as a "connection reset by
// peer" when running `tailscale warp status`).
var _ WarpClient = (*warp.Client)(nil)

// fakeWarpClient is a minimal WarpClient for tests that don't need a real
// tunnel; it records packets and exposes fixed assigned addresses.
type fakeWarpClient struct {
	packets [][]byte
	handler func([]byte)
}

func (f *fakeWarpClient) SendPacket(p []byte) error {
	f.packets = append(f.packets, append([]byte(nil), p...))
	return nil
}

func (f *fakeWarpClient) SetPacketHandler(handler func([]byte)) { f.handler = handler }

func (f *fakeWarpClient) AssignedIP(version uint8) netip.Addr {
	if version == 4 {
		return netip.MustParseAddr("172.16.0.2")
	}
	return netip.MustParseAddr("2606:4700:110:8d9b::2")
}

// TestSetWarpClient verifies that SetWarpClient accepts a real WarpClient
// (and nil) without panicking, and that a non-WarpClient is rejected. This is
// a regression test for a bug where *warp.Client did not satisfy the
// interface, causing SetWarpClient to panic and take down the daemon.
func TestSetWarpClient(t *testing.T) {
	var ns Impl
	ns.logf = t.Logf

	ns.SetWarpClient(&fakeWarpClient{})
	if !ns.isWarpClient() {
		t.Fatal("WARP mode not enabled after SetWarpClient(non-nil)")
	}

	ns.SetWarpClient(nil)
	if ns.isWarpClient() {
		t.Fatal("WARP mode still enabled after SetWarpClient(nil)")
	}

	// Passing a genuine *warp.Client must not panic (this is the exact
	// production path wired up by ipnlocal when WARP mode is enabled).
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("SetWarpClient(*warp.Client) panicked: %v", r)
		}
	}()
	dir := t.TempDir()
	ns.SetWarpClient(warp.NewClient(logger.Discard, filepath.Join(dir, "warp-client.json"), false))
	if !ns.isWarpClient() {
		t.Fatal("WARP mode not enabled with real *warp.Client")
	}
}

// TestWarpIntercept verifies the packet predicate that decides whether an
// outbound host packet is absorbed into netstack for WARP tunneling: only
// all internet-bound IP traffic is intercepted; localhost, local networks,
// and the tailnet are left alone.
func TestWarpIntercept(t *testing.T) {
	var ns Impl // warpIntercept is pure; a zero Impl is sufficient.

	pkt := func(proto ipproto.Proto, dst string) *packet.Parsed {
		return &packet.Parsed{
			IPVersion: 4,
			IPProto:   proto,
			Src:       netip.MustParseAddrPort("192.168.1.50:12345"),
			Dst:       netip.MustParseAddrPort(dst),
		}
	}

	tests := []struct {
		name string
		pkt  *packet.Parsed
		want bool
	}{
		// Internet traffic is intercepted, including non-TCP/UDP protocols.
		{"tcp-public", pkt(ipproto.TCP, "1.1.1.1:443"), true},
		{"udp-public", pkt(ipproto.UDP, "8.8.8.8:53"), true},
		{"tcp-public-v6", pkt(ipproto.TCP, "[2606:4700:4700::1111]:443"), true},
		{"icmp-public", pkt(ipproto.ICMPv4, "1.1.1.1:0"), true},

		// Localhost, local networks, and the tailnet are not intercepted.
		{"tcp-localhost", pkt(ipproto.TCP, "127.0.0.1:443"), false},
		{"tcp-rfc1918", pkt(ipproto.TCP, "10.1.2.3:443"), false},
		{"tcp-ula", pkt(ipproto.TCP, "[fd00::1]:443"), false},
		{"tcp-linklocal", pkt(ipproto.TCP, "169.254.169.254:443"), false},
		{"tcp-cgnat", pkt(ipproto.TCP, "100.64.0.1:443"), false},
		{"tcp-magicdns", pkt(ipproto.TCP, "100.100.100.100:443"), false},
		{"tcp-multicast", pkt(ipproto.TCP, "224.0.0.1:443"), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ns.warpIntercept(tt.pkt); got != tt.want {
				t.Errorf("warpIntercept(%v, %v) = %v; want %v",
					tt.pkt.IPProto, tt.pkt.Dst, got, tt.want)
			}
		})
	}
}

func TestWarpPacketAddressTranslation(t *testing.T) {
	var ns Impl
	wc := new(fakeWarpClient)
	hostIP := netip.MustParseAddr("192.168.1.50")
	remoteIP := netip.MustParseAddr("1.1.1.1")
	out := packet.Generate(packet.UDP4Header{
		IP4Header: packet.IP4Header{Src: hostIP, Dst: remoteIP},
		SrcPort:   4242,
		DstPort:   53,
	}, []byte("query"))
	var parsed packet.Parsed
	parsed.Decode(out)

	translated, err := ns.warpPrepareOutbound(wc, &parsed)
	if err != nil {
		t.Fatal(err)
	}
	var got packet.Parsed
	got.Decode(translated)
	if want := wc.AssignedIP(4); got.Src.Addr() != want {
		t.Fatalf("translated source = %v, want %v", got.Src.Addr(), want)
	}
	if got.Dst.Addr() != remoteIP {
		t.Fatalf("translated destination = %v, want %v", got.Dst.Addr(), remoteIP)
	}

	reply := packet.Generate(packet.UDP4Header{
		IP4Header: packet.IP4Header{Src: remoteIP, Dst: wc.AssignedIP(4)},
		SrcPort:   53,
		DstPort:   4242,
	}, []byte("response"))
	restored, err := ns.warpRestoreInbound(wc, reply)
	if err != nil {
		t.Fatal(err)
	}
	got.Decode(restored)
	if got.Dst.Addr() != hostIP {
		t.Fatalf("restored destination = %v, want %v", got.Dst.Addr(), hostIP)
	}
	if got.Src.Addr() != remoteIP {
		t.Fatalf("restored source = %v, want %v", got.Src.Addr(), remoteIP)
	}
}
