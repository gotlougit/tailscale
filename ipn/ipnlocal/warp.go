// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package ipnlocal

import (
	"context"
	"errors"
	"net/netip"
	"path/filepath"
	"time"

	"tailscale.com/feature/buildfeatures"
	"tailscale.com/health"
	"tailscale.com/ipn"
	"tailscale.com/net/warp"
)

// warnWarpUnhealthy is shown when WARP mode is on but the tunnel to
// Cloudflare's edge is down (or registration has not succeeded yet).
var warnWarpUnhealthy = health.Register(&health.Warnable{
	Code:     "warp-unhealthy",
	Title:    "WARP connection unhealthy",
	Severity: health.SeverityMedium,
	Text:     health.StaticMessage("warp mode is on, but no usable WARP tunnel is up; internet traffic is being blackholed until it reconnects"),
})

// warpClient is the active WARP client, or nil when WARP mode is off.
// Guarded by b.mu.
func (b *LocalBackend) warpClient() *warp.Client {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.warp
}

// warpSetNetstack installs (or removes, with nil) the WARP hook on the
// netstack Impl so internet-bound traffic is tunneled through wc.
//
// b.mu must be held.
func (b *LocalBackend) warpSetNetstackLocked(wc *warp.Client) {
	if ns, ok := b.sys.Netstack.GetOK(); ok {
		var v any
		if wc != nil {
			v = wc
		}
		ns.SetWarpClient(v)
	}
}

// warpConfigPath returns the path where the WARP registration is persisted.
// It is empty (and WARP is unavailable) if there's no Tailscale state
// directory.
//
// b.mu must be held.
func (b *LocalBackend) warpConfigPathLocked() string {
	vr := b.TailscaleVarRoot()
	if vr == "" {
		return ""
	}
	return filepath.Join(vr, "warp-client.json")
}

// updateWarpLocked transitions the WARP client to match prefs. It must not
// block on network I/O; the actual registration and tunnel bring-up happen
// in a background goroutine.
//
// b.mu must be held.
func (b *LocalBackend) updateWarpLocked(prefs ipn.PrefsView) {
	want := buildfeatures.HasWarp && prefs.WarpMode()
	if b.warp != nil && !want {
		// Turn WARP off.
		wc := b.warp
		b.warp = nil
		b.warpSetNetstackLocked(nil)
		b.health.SetHealthy(warnWarpUnhealthy)
		b.goTracker.Go(func() { wc.Close() })
		return
	}
	if b.warp == nil && want {
		cfgPath := b.warpConfigPathLocked()
		if cfgPath == "" {
			b.logf("warp: cannot enable WARP mode: no Tailscale state directory")
			b.health.SetUnhealthy(warnWarpUnhealthy, health.Args{health.ArgError: "no Tailscale state directory"})
			return
		}
		wc := warp.NewClient(b.logf, cfgPath, false)
		b.warp = wc
		b.goTracker.Go(func() { b.warpEnsureRunning(wc) })
	}
}

// warpIsCurrent reports whether wc is still the active WARP client (i.e. the
// user has not toggled WARP off since wc was created).
func (b *LocalBackend) warpIsCurrent(wc *warp.Client) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.warp == wc
}

// warpEnsureRunning brings the WARP client up: registering with Cloudflare
// (which implies accepting their Terms of Service) if no registration exists
// yet, starting the MASQUE tunnel, and then monitoring it until WARP mode is
// turned off. Failures are retried with backoff and reported to health.
func (b *LocalBackend) warpEnsureRunning(wc *warp.Client) {
	backoff := time.Second
	for b.warpIsCurrent(wc) {
		if !wc.Registered() {
			if err := wc.Register(context.Background()); err != nil {
				b.logf("warp: registration failed: %v", err)
				b.warpSetHealthError(wc, err)
				if !b.warpWaitRetry(wc, &backoff) {
					return
				}
				continue
			}
			b.logf("warp: registered new WARP device")
		}
		if err := wc.Start(context.Background()); err != nil {
			b.logf("warp: start failed: %v", err)
			b.warpSetHealthError(wc, err)
			if !b.warpWaitRetry(wc, &backoff) {
				return
			}
			continue
		}
		b.mu.Lock()
		b.warpSetNetstackLocked(wc)
		b.mu.Unlock()
		b.health.SetHealthy(warnWarpUnhealthy)
		backoff = time.Second

		// Block until WARP mode is turned off (or the client otherwise
		// stops); the client's maintenance loop handles reconnecting the
		// tunnel on its own.
		<-wc.Done()
		if !b.warpIsCurrent(wc) {
			return
		}
		b.warpSetHealthError(wc, errors.New("warp: tunnel stopped"))
		b.mu.Lock()
		b.warpSetNetstackLocked(nil)
		b.mu.Unlock()
		if !b.warpWaitRetry(wc, &backoff) {
			return
		}
	}
}

// warpSetHealthError reports a WARP failure to the health tracker and logs it
// once per transition.
func (b *LocalBackend) warpSetHealthError(wc *warp.Client, err error) {
	b.logf("warp: %v", err)
	b.health.SetUnhealthy(warnWarpUnhealthy, health.Args{health.ArgError: err.Error()})
}

// warpWaitRetry waits for the WARP retry backoff, returning false if WARP
// mode was turned off (or the client was superseded) while waiting.
func (b *LocalBackend) warpWaitRetry(wc *warp.Client, backoff *time.Duration) bool {
	timer := time.NewTimer(*backoff)
	defer timer.Stop()
	select {
	case <-wc.Done():
		return false
	case <-timer.C:
	}
	if *backoff > 30*time.Second {
		*backoff = 30 * time.Second
	} else {
		*backoff *= 2
	}
	return b.warpIsCurrent(wc)
}

// WarpStatus returns the current WARP status for the LocalAPI, or nil when
// WARP mode is off or unavailable.
func (b *LocalBackend) WarpStatus() *warp.Status {
	wc := b.warpClient()
	if wc == nil {
		return &warp.Status{}
	}
	st := wc.Status()
	st.Enabled = true
	return &st
}

// reconcileWarpPrefsLocked enforces that WARP mode is mutually exclusive with
// selecting a tailnet exit node: when WARP mode is on, any explicitly chosen
// exit node is dropped (WARP takes over internet routing). It reports whether
// it modified p.
//
// b.mu must be held.
func (b *LocalBackend) reconcileWarpPrefsLocked(p *ipn.Prefs) (changed bool) {
	if !p.WarpMode {
		return false
	}
	if p.ExitNodeID != "" || p.ExitNodeIP.IsValid() || p.AutoExitNode != "" {
		b.logf("warp: disabling exit node selection (exit node and WARP are mutually exclusive)")
		changed = true
	}
	p.ExitNodeID = ""
	p.ExitNodeIP = netip.Addr{}
	p.AutoExitNode = ""
	return changed
}