// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !linux

package warp

import (
	"net"
)

// setListenSocketBypassMark is a no-op on non-Linux platforms.
func setListenSocketBypassMark(conn *net.UDPConn) error {
	return nil
}
