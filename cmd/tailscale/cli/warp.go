// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package cli

import (
	"context"
	"encoding/json"
	"strings"
	"errors"
	"flag"
	"fmt"

	"github.com/peterbourgon/ff/v3/ffcli"
	"tailscale.com/ipn"
)

var warpCmd = &ffcli.Command{
	Name:       "warp",
	ShortUsage: "tailscale warp [on|off|status]",
	ShortHelp:  "Route internet traffic through Cloudflare WARP",
	LongHelp: strings.TrimSpace(`
The 'tailscale warp' command controls whether internet-bound traffic that
isn't covered by localhost, local networks, or the tailnet is routed through
Cloudflare WARP (over a MASQUE connection) instead of directly.

Running 'tailscale warp on' registers this device with Cloudflare WARP if
necessary, which accepts Cloudflare's WARP Terms of Service.

Subcommands:
  on       Turn WARP mode on
  off      Turn WARP mode off
  status   Show WARP registration and tunnel status
`),
	Exec: runWarpStatus,
	FlagSet: (func() *flag.FlagSet {
		fs := newFlagSet("warp")
		return fs
	})(),
	Subcommands: []*ffcli.Command{
		{
			Name:       "on",
			ShortUsage: "tailscale warp on",
			ShortHelp:  "Route internet traffic through Cloudflare WARP",
			Exec:       runWarpOn,
			FlagSet: (func() *flag.FlagSet {
				return newFlagSet("on")
			})(),
		},
		{
			Name:       "off",
			ShortUsage: "tailscale warp off",
			ShortHelp:  "Stop routing internet traffic through Cloudflare WARP",
			Exec:       runWarpOff,
			FlagSet: (func() *flag.FlagSet {
				return newFlagSet("off")
			})(),
		},
		{
			Name:       "status",
			ShortUsage: "tailscale warp status",
			ShortHelp:  "Show WARP registration and tunnel status",
			Exec:       runWarpStatus,
			FlagSet: (func() *flag.FlagSet {
				return newFlagSet("status")
			})(),
		},
	},
}

func runWarpOn(ctx context.Context, args []string) error {
	if len(args) > 0 {
		return errors.New("warp on: unexpected arguments")
	}
	// Turning WARP on implies accepting Cloudflare's WARP Terms of
	// Service; the daemon registers a WARP device if one isn't already
	// registered.
	prefs, err := localClient.EditPrefs(ctx, &ipn.MaskedPrefs{
		Prefs: ipn.Prefs{
			WarpMode:    true,
			WantRunning: true,
		},
		WarpModeSet:    true,
		WantRunningSet: true,
	})
	if err != nil {
		return fmt.Errorf("warp on: %w", err)
	}
	if !prefs.WarpMode {
		return errors.New("warp on: WARP mode was not enabled (prefs rejected by policy?)")
	}
	outln("WARP mode on: internet traffic will be routed through Cloudflare WARP.")
	return runWarpStatus(ctx, nil)
}

func runWarpOff(ctx context.Context, args []string) error {
	if len(args) > 0 {
		return errors.New("warp off: unexpected arguments")
	}
	prefs, err := localClient.EditPrefs(ctx, &ipn.MaskedPrefs{
		Prefs:       ipn.Prefs{WarpMode: false},
		WarpModeSet: true,
	})
	if err != nil {
		return fmt.Errorf("warp off: %w", err)
	}
	if prefs.WarpMode {
		return errors.New("warp off: WARP mode is still enabled")
	}
	outln("WARP mode off: internet traffic will be sent directly again.")
	return nil
}

// warpStatusJSON mirrors tailscale.com/net/warp.Status; it is duplicated here
// so the CLI doesn't have to link in the WARP client (and quic-go).
type warpStatusJSON struct {
	Enabled    bool   `json:"enabled"`
	Registered bool   `json:"registered"`
	Connected  bool   `json:"connected"`
	DeviceID   string `json:"deviceId,omitempty"`
	Endpoint   string `json:"endpoint,omitempty"`
	EndpointIP string `json:"endpointIp,omitempty"`
	IPv4       string `json:"ipv4,omitempty"`
	LastError  string `json:"lastError,omitempty"`
}

func runWarpStatus(ctx context.Context, args []string) error {
	if len(args) > 0 {
		return errors.New("warp status: unexpected arguments")
	}
	raw, err := localClient.WarpStatus(ctx)
	if err != nil {
		return fmt.Errorf("warp status: %w", err)
	}
	var st warpStatusJSON
	if err := json.Unmarshal(raw, &st); err != nil {
		return fmt.Errorf("warp status: invalid daemon response: %w", err)
	}
	outln(fmt.Sprintf("WARP mode: %s", onOrOff(st.Enabled)))
	outln(fmt.Sprintf("WARP device registered: %s", yesOrNo(st.Registered)))
	if st.Registered {
		if st.DeviceID != "" {
			outln(fmt.Sprintf("Device ID: %s", st.DeviceID))
		}
		if st.IPv4 != "" {
			outln(fmt.Sprintf("WARP IPv4: %s", st.IPv4))
		}
	}
	outln(fmt.Sprintf("Tunnel: %s", tunnelState(st)))
	return nil
}

func onOrOff(b bool) string {
	if b {
		return "on"
	}
	return "off"
}

func yesOrNo(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}

func tunnelState(st warpStatusJSON) string {
	if !st.Enabled {
		return "off (warp mode not enabled)"
	}
	if !st.Registered {
		if st.LastError != "" {
			return fmt.Sprintf("dead (registration failed: %s)", st.LastError)
		}
		return "dead (not registered)"
	}
	if st.Connected {
		return fmt.Sprintf("connected to %s", st.Endpoint)
	}
	if st.LastError != "" {
		return fmt.Sprintf("disconnected (%s)", st.LastError)
	}
	return "disconnected"
}