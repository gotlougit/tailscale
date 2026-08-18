// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package warp

import (
	"net/netip"

	"tailscale.com/net/tsaddr"
)

// Interceptable reports whether a destination address is "internet" traffic —
// that is, traffic not covered by localhost, local networks, or the tailnet —
// and therefore eligible to be routed over WARP.
//
// Specifically excluded (and left to be routed directly):
//
//   - loopback (127.0.0.0/8, ::1)
//   - private / local networks (RFC 1918 10/8, 172.16/12, 192.168/16; ULA fc00::/7)
//   - link-local (169.254/16, fe80::/10)
//   - multicast (224.0.0.0/4, ff00::/8)
//   - unspecified, 0.0.0.0/8 and broadcast addresses
//   - the tailnet itself and the CGNAT space it lives in (100.64.0.0/10
//     plus Tailscale's ULA), including MagicDNS's 100.100.100.100
func Interceptable(dst netip.Addr) bool {
	dst = dst.Unmap()
	if !dst.IsValid() {
		return false
	}
	if dst.IsLoopback() ||
		dst.IsPrivate() ||
		dst.IsLinkLocalUnicast() ||
		dst.IsLinkLocalMulticast() ||
		dst.IsMulticast() ||
		dst.IsUnspecified() {
		return false
	}
	if dst.Is4() {
		b := dst.As4()
		if b[0] == 0 || // 0.0.0.0/8 "this network"
			b == [4]byte{255, 255, 255, 255} { // limited broadcast
			return false
		}
	}
	return !tsaddr.IsTailscaleIP(dst)
}