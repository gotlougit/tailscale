// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package ipnlocal

import (
	"net/netip"
	"testing"

	"tailscale.com/ipn"
)

// TestReconcileWarpPrefs verifies that WARP mode is mutually exclusive with
// selecting a tailnet exit node: enabling WARP drops any explicitly chosen
// exit node, and leaving WARP off leaves exit-node prefs untouched.
func TestReconcileWarpPrefs(t *testing.T) {
	lb := newTestLocalBackend(t)

	tests := []struct {
		name     string
		prefs    func() *ipn.Prefs
		wantChg  bool
		wantNode string // expected ExitNodeID after reconcile ("" = cleared)
	}{
		{
			name: "warp-off-leaves-exit-node",
			prefs: func() *ipn.Prefs {
				return &ipn.Prefs{ExitNodeID: "n1"}
			},
			wantChg:  false,
			wantNode: "n1",
		},
		{
			name: "warp-on-clears-exit-node-id",
			prefs: func() *ipn.Prefs {
				return &ipn.Prefs{WarpMode: true, ExitNodeID: "n1"}
			},
			wantChg:  true,
			wantNode: "",
		},
		{
			name: "warp-on-clears-exit-node-ip",
			prefs: func() *ipn.Prefs {
				return &ipn.Prefs{WarpMode: true, ExitNodeIP: netip.MustParseAddr("100.101.102.103")}
			},
			wantChg: true,
		},
		{
			name: "warp-on-clears-auto-exit-node",
			prefs: func() *ipn.Prefs {
				return &ipn.Prefs{WarpMode: true, AutoExitNode: "any"}
			},
			wantChg: true,
		},
		{
			name: "warp-on-no-exit-node-unchanged",
			prefs: func() *ipn.Prefs {
				return &ipn.Prefs{WarpMode: true}
			},
			wantChg: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := tt.prefs()
			lb.mu.Lock()
			changed := lb.reconcileWarpPrefsLocked(p)
			lb.mu.Unlock()
			if changed != tt.wantChg {
				t.Errorf("changed = %v; want %v", changed, tt.wantChg)
			}
			if tt.name == "warp-off-leaves-exit-node" {
				if string(p.ExitNodeID) != tt.wantNode {
					t.Errorf("ExitNodeID = %q; want %q", p.ExitNodeID, tt.wantNode)
				}
			} else {
				if p.ExitNodeID != "" || p.ExitNodeIP.IsValid() || p.AutoExitNode != "" {
					t.Errorf("exit node prefs not cleared: id=%q ip=%v auto=%q",
						p.ExitNodeID, p.ExitNodeIP, p.AutoExitNode)
				}
			}
		})
	}
}
