// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

// WARP integration: tunnels internet-bound traffic through a Cloudflare
// WARP CONNECT-IP stream.
//
// The OS routes internet-bound packets into the Tailscale interface. We copy
// each packet, translate its source to the address Cloudflare assigned this
// WARP registration, and send the complete IP packet over HTTP/3 datagrams.
// Reply packets have that translation reversed and are injected into the host.
package netstack

import (
	"fmt"
	"net/netip"
	"time"

	"tailscale.com/net/packet"
	"tailscale.com/net/packet/checksum"
	"tailscale.com/net/warp"
	"tailscale.com/types/ipproto"
)

const warpFlowIdleTimeout = 5 * time.Minute

// WarpClient is the subset of the *warp.Client API that netstack needs.
type WarpClient interface {
	SendPacket([]byte) error
	SetPacketHandler(func([]byte))
	AssignedIP(version uint8) netip.Addr
}

type warpFlowKey struct {
	proto      ipproto.Proto
	localPort  uint16
	remoteAddr netip.AddrPort
}

type warpFlow struct {
	originalSrc netip.Addr
	lastUsed    time.Time
}

// SetWarpClient enables or disables WARP mode on this netstack. When wc is
// non-nil, internet-bound IP packets are tunneled through it; a nil value
// disables interception. The change takes effect for subsequent packets.
//
// The parameter is typed as any so that tsd.NetstackImpl can expose it
// without an import cycle; it must be a WarpClient or nil.
func (ns *Impl) SetWarpClient(wc any) {
	var c WarpClient
	if wc != nil {
		var ok bool
		c, ok = wc.(WarpClient)
		if !ok {
			panic(fmt.Sprintf("netstack: SetWarpClient: unexpected type %T", wc))
		}
	}

	generation := ns.warpGeneration.Add(1)
	old := ns.warpClient.Swap(c)
	if old != nil {
		old.SetPacketHandler(nil)
	}
	ns.warpMu.Lock()
	clear(ns.warpFlows)
	ns.warpFallback4 = netip.Addr{}
	ns.warpFallback6 = netip.Addr{}
	ns.warpLastGC = time.Time{}
	ns.warpMu.Unlock()

	if c != nil {
		c.SetPacketHandler(func(raw []byte) {
			if ns.warpGeneration.Load() != generation {
				return
			}
			ns.warpInjectInbound(c, raw)
		})
	}
	ns.logf("netstack: WARP mode %v", c != nil)
}

// isWarpClient reports whether WARP mode is currently enabled.
func (ns *Impl) isWarpClient() bool {
	return ns.warpClient.Load() != nil
}

// warpIntercept reports whether an outbound packet from the host should be
// sent through WARP. Localhost, local networks, and tailnet destinations are
// deliberately excluded by warp.Interceptable.
func (ns *Impl) warpIntercept(p *packet.Parsed) bool {
	dst := p.Dst.Addr()
	if !warp.Interceptable(dst) {
		return false
	}
	if debugPackets {
		ns.logf("[v2] netstack: warp: intercepting %s packet to %v", p.IPProto, dst)
	}
	return true
}

// warpSendOutbound copies, source-NATs, and sends one host packet through the
// CONNECT-IP tunnel.
func (ns *Impl) warpSendOutbound(p *packet.Parsed) error {
	wc := ns.warpClient.Load()
	if wc == nil {
		return fmt.Errorf("WARP client was disabled")
	}
	raw, err := ns.warpPrepareOutbound(wc, p)
	if err != nil {
		return err
	}
	return wc.SendPacket(raw)
}

func (ns *Impl) warpPrepareOutbound(wc WarpClient, p *packet.Parsed) ([]byte, error) {
	assigned := wc.AssignedIP(p.IPVersion)
	if !assigned.IsValid() || assigned.Is4() != (p.IPVersion == 4) {
		return nil, fmt.Errorf("no WARP-assigned IPv%d address", p.IPVersion)
	}

	raw := append([]byte(nil), p.Buffer()...)
	var q packet.Parsed
	q.Decode(raw)
	if q.IPVersion != p.IPVersion {
		return nil, fmt.Errorf("invalid outbound IPv%d packet", p.IPVersion)
	}

	ns.warpRememberFlow(&q)
	checksum.UpdateSrcAddr(&q, assigned)
	return raw, nil
}

func (ns *Impl) warpRememberFlow(p *packet.Parsed) {
	now := time.Now()
	key := warpFlowKey{
		proto:      p.IPProto,
		localPort:  p.Src.Port(),
		remoteAddr: p.Dst,
	}
	ns.warpMu.Lock()
	if ns.warpFlows == nil {
		ns.warpFlows = make(map[warpFlowKey]warpFlow)
	}
	ns.warpFlows[key] = warpFlow{originalSrc: p.Src.Addr(), lastUsed: now}
	if p.IPVersion == 4 {
		ns.warpFallback4 = p.Src.Addr()
	} else {
		ns.warpFallback6 = p.Src.Addr()
	}
	if now.Sub(ns.warpLastGC) >= time.Minute {
		for key, flow := range ns.warpFlows {
			if now.Sub(flow.lastUsed) > warpFlowIdleTimeout {
				delete(ns.warpFlows, key)
			}
		}
		ns.warpLastGC = now
	}
	ns.warpMu.Unlock()
}

func (ns *Impl) warpInjectInbound(wc WarpClient, raw []byte) {
	packet, err := ns.warpRestoreInbound(wc, raw)
	if err != nil {
		ns.logf("netstack: warp: dropping inbound packet: %v", err)
		return
	}
	if err := ns.tundev.InjectInboundCopy(packet); err != nil {
		ns.logf("netstack: warp: injecting inbound packet: %v", err)
	}
}

func (ns *Impl) warpRestoreInbound(wc WarpClient, raw []byte) ([]byte, error) {
	var p packet.Parsed
	p.Decode(raw)
	if p.IPVersion != 4 && p.IPVersion != 6 {
		return nil, fmt.Errorf("invalid IP packet")
	}
	assigned := wc.AssignedIP(p.IPVersion)
	if !assigned.IsValid() || p.Dst.Addr() != assigned {
		return nil, fmt.Errorf("packet addressed to %v, not assigned address %v", p.Dst.Addr(), assigned)
	}

	key := warpFlowKey{
		proto:      p.IPProto,
		localPort:  p.Dst.Port(),
		remoteAddr: p.Src,
	}
	ns.warpMu.Lock()
	flow, ok := ns.warpFlows[key]
	if ok {
		flow.lastUsed = time.Now()
		ns.warpFlows[key] = flow
	}
	fallback := ns.warpFallback6
	if p.IPVersion == 4 {
		fallback = ns.warpFallback4
	}
	ns.warpMu.Unlock()

	originalDst := fallback
	if ok {
		originalDst = flow.originalSrc
	}
	if !originalDst.IsValid() {
		return nil, fmt.Errorf("no matching outbound flow for %v", p)
	}
	checksum.UpdateDstAddr(&p, originalDst)
	return raw, nil
}
