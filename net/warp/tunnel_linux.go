// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package warp

import (
	"net"

	"golang.org/x/sys/unix"
	"tailscale.com/tsconst"
)

// setListenSocketBypassMark sets SO_MARK on the UDP listener socket so that
// packets sent by the WARP tunnel's QUIC connection bypass the Tailscale
// routing table (table 52). Without this mark, the QUIC packets would be
// routed into the TUN interface and intercepted by netstack's WARP hook,
// creating a self-loop that causes "QUIC dial failed: timeout: no recent
// network activity".
func setListenSocketBypassMark(conn *net.UDPConn) error {
	raw, err := conn.SyscallConn()
	if err != nil {
		return err
	}
	var sockErr error
	if err := raw.Control(func(fd uintptr) {
		sockErr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_MARK, tsconst.LinuxBypassMarkNum)
	}); err != nil {
		return err
	}
	return sockErr
}
