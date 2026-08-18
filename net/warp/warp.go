// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package warp

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"tailscale.com/syncs"
	"tailscale.com/types/logger"
)

// Client manages a WARP registration and its MASQUE tunnel, keeping the
// connection to Cloudflare's edge alive while enabled.
//
// Registration is a one-time cost (per device); the resulting config is
// persisted to configPath. A Client whose config is missing or invalid must
// be (re)registered before Start can succeed.
//
// A Client is safe for concurrent use.
type Client struct {
	logf       logger.Logf
	configPath string
	useIPv6    bool

	mu     sync.Mutex // guards cfg and tunnel
	cfg    *Config
	tunnel *Tunnel

	connected     atomic.Bool  // tunnel is (probably) up
	lastErr       atomic.Value // string; last connection error, "" if none
	packetHandler syncs.AtomicValue[func([]byte)]

	stop  chan struct{} // closed by Close
	stopc sync.Once
	wg    sync.WaitGroup
}

// NewClient returns a Client that persists its WARP registration at
// configPath. It performs no I/O.
func NewClient(logf logger.Logf, configPath string, useIPv6 bool) *Client {
	if logf == nil {
		logf = logger.Discard
	}
	c := &Client{
		logf:       logger.WithPrefix(logf, "warp: "),
		configPath: configPath,
		useIPv6:    useIPv6,
		stop:       make(chan struct{}),
	}
	c.lastErr.Store("")
	return c
}

// ConfigPath returns the path to the persisted registration config.
func (c *Client) ConfigPath() string { return c.configPath }

// Register performs the two-step WARP registration (accepting Cloudflare's
// Terms of Service, as implied by the caller) and persists the resulting
// config. It is an error to call Register while the client is running.
func (c *Client) Register(ctx context.Context) error {
	c.mu.Lock()
	running := c.tunnel != nil
	c.mu.Unlock()
	if running {
		return errors.New("warp: cannot re-register while running")
	}
	cfg, err := Register(ctx, c.logf)
	if err != nil {
		return err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.tunnel != nil {
		return errors.New("warp: cannot re-register while running")
	}
	if err := cfg.Save(c.configPath); err != nil {
		return err
	}
	c.cfg = cfg
	return nil
}

// Registered reports whether a valid registration config exists on disk.
// It does not require the client to be running.
func (c *Client) Registered() bool {
	var cfg Config
	if err := cfg.Load(c.configPath); err != nil {
		return false
	}
	return cfg.Valid()
}

// LoadRegistration reads the persisted registration, if any. It is used by
// callers that want to display registration details without starting the
// tunnel.
func (c *Client) LoadRegistration() (*Config, error) {
	var cfg Config
	if err := cfg.Load(c.configPath); err != nil {
		if os.IsNotExist(err) {
			return nil, errors.New("warp: no valid registration at " + c.configPath)
		}
		return nil, err
	}
	if !cfg.Valid() {
		return nil, errors.New("warp: no valid registration at " + c.configPath)
	}
	return &cfg, nil
}

// Start loads the registration and brings up the MASQUE tunnel to the edge,
// then maintains it (re-dialing after failures) until Close.
func (c *Client) Start(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.tunnel != nil {
		return errors.New("warp: already started")
	}
	cfg, err := c.LoadRegistration()
	if err != nil {
		return err
	}
	tunnel, err := NewTunnel(c.logf, cfg, c.useIPv6)
	if err != nil {
		return err
	}
	connectCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	packetTunnel, err := tunnel.ensurePacketConnected(connectCtx)
	cancel()
	if err != nil {
		_ = tunnel.Close()
		c.lastErr.Store(err.Error())
		return err
	}
	c.cfg = cfg
	c.tunnel = tunnel
	c.connected.Store(true)
	c.lastErr.Store("")

	c.wg.Add(1)
	go c.maintain(packetTunnel)
	return nil
}

// Dial opens a TCP connection through the WARP tunnel to address. See
// [Tunnel.Dial].
func (c *Client) Dial(ctx context.Context, network, address string) (net.Conn, error) {
	c.mu.Lock()
	t := c.tunnel
	c.mu.Unlock()
	if t == nil {
		return nil, errors.New("warp: not started")
	}
	conn, err := t.Dial(ctx, network, address)
	c.noteErr(err)
	return conn, err
}

// SendPacket sends a complete IPv4 or IPv6 packet through the active
// Cloudflare CONNECT-IP tunnel. packet may be modified in place.
func (c *Client) SendPacket(packet []byte) error {
	c.mu.Lock()
	t := c.tunnel
	c.mu.Unlock()
	if t == nil {
		return errors.New("warp: not started")
	}
	err := t.SendPacket(packet)
	c.noteErr(err)
	return err
}

// SetPacketHandler sets the function called for packets received from the
// CONNECT-IP tunnel. A nil handler drops received packets.
func (c *Client) SetPacketHandler(handler func([]byte)) {
	c.packetHandler.Store(handler)
}

// AssignedIP returns the IPv4 or IPv6 address assigned to this WARP
// registration. version must be 4 or 6.
func (c *Client) AssignedIP(version uint8) netip.Addr {
	c.mu.Lock()
	cfg := c.cfg
	c.mu.Unlock()
	if cfg == nil {
		return netip.Addr{}
	}
	var s string
	switch version {
	case 4:
		s = cfg.IPv4
	case 6:
		s = cfg.IPv6
	default:
		return netip.Addr{}
	}
	if addr, err := netip.ParseAddr(s); err == nil {
		return addr
	}
	if prefix, err := netip.ParsePrefix(s); err == nil {
		return prefix.Addr()
	}
	return netip.Addr{}
}

// Status reports the current state of the client.
func (c *Client) Status() Status {
	c.mu.Lock()
	defer c.mu.Unlock()
	cfg := c.cfg
	if cfg == nil {
		// Fall back to the on-disk config if the client hasn't been
		// started yet (e.g., the daemon was restarted but WARP was
		// previously registered).
		var onDisk Config
		if err := onDisk.Load(c.configPath); err == nil && onDisk.Valid() {
			cfg = &onDisk
		}
	}
	st := Status{
		Registered: cfg != nil,
		Connected:  c.connected.Load(),
		DeviceID:   "",
	}
	if cfg != nil {
		st.DeviceID = cfg.ID
		if c.tunnel != nil {
			st.Endpoint = c.tunnel.Endpoint()
			st.EndpointIP = c.tunnel.EndpointIP()
		}
		st.IPv4 = cfg.IPv4
	}
	if le, ok := c.lastErr.Load().(string); ok && le != "" {
		st.LastError = le
	}
	return st
}

// Close stops the tunnel and the maintenance goroutine. It returns quickly;
// the maintenance goroutine may take a moment to observe the shutdown.
// Callers that need to wait for full cleanup should call [Client.Wait] after
// Close.
func (c *Client) Close() error {
	c.stopc.Do(func() { close(c.stop) })
	c.mu.Lock()
	t := c.tunnel
	c.tunnel = nil
	c.mu.Unlock()
	if t != nil {
		t.Close()
	}
	c.connected.Store(false)
	return nil
}

// Wait blocks until the maintenance goroutine (started by [Client.Start]) has
// fully exited. It should be called after [Client.Close] when the caller needs
// to ensure the goroutine is done before e.g. creating a new Client for the
// same config path.
func (c *Client) Wait() {
	c.wg.Wait()
}

// Done is closed when the client is closed (via [Client.Close]).
func (c *Client) Done() <-chan struct{} { return c.stop }

// maintain receives packets and re-establishes CONNECT-IP after failures.
func (c *Client) maintain(pc *packetTunnel) {
	defer c.wg.Done()
	backoff := 1 * time.Second
	for {
		if pc != nil {
			packet, err := pc.ReadPacket()
			if err == nil {
				if handler := c.packetHandler.Load(); handler != nil {
					handler(packet)
				}
				continue
			}
			c.mu.Lock()
			t := c.tunnel
			c.mu.Unlock()
			if t != nil {
				t.invalidatePacket(pc)
			}
			pc = nil
			c.connected.Store(false)
			c.noteErr(err)
			select {
			case <-c.stop:
				return
			default:
			}
			c.logf("WARP packet tunnel down: %v; retrying in %v", err, backoff)
		}

		select {
		case <-c.stop:
			return
		case <-time.After(backoff):
		}

		c.mu.Lock()
		t := c.tunnel
		c.mu.Unlock()
		if t == nil {
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		var err error
		pc, err = t.ensurePacketConnected(ctx)
		cancel()
		if err != nil {
			c.connected.Store(false)
			c.noteErr(err)
			c.logf("WARP packet tunnel reconnect failed: %v; retrying in %v", err, backoff)
			backoff = min(backoff*2, 30*time.Second)
			continue
		}
		c.connected.Store(true)
		c.lastErr.Store("")
		backoff = 1 * time.Second
	}
}

// noteErr records err in the client's last-error state, if any.
func (c *Client) noteErr(err error) {
	if err == nil {
		return
	}
	c.lastErr.Store(err.Error())
}

// Status describes the state of a WARP client, as reported to the CLI.
type Status struct {
	// Enabled reports whether WARP mode is on (the client is active).
	Enabled bool `json:"enabled"`
	// Registered reports whether a valid registration exists.
	Registered bool `json:"registered"`
	// Connected reports whether the tunnel to the edge is up.
	Connected bool `json:"connected"`
	// DeviceID is Cloudflare's registration id, if registered.
	DeviceID string `json:"deviceId,omitempty"`
	// Endpoint is the dialed edge endpoint "ip:port".
	Endpoint string `json:"endpoint,omitempty"`
	// EndpointIP is the edge endpoint IP, without port.
	EndpointIP string `json:"endpointIp,omitempty"`
	// IPv4 is the WARP-assigned device IPv4, if registered.
	IPv4 string `json:"ipv4,omitempty"`
	// LastError is the most recent connection error, if any.
	LastError string `json:"lastError,omitempty"`
}

// IsWARPConfigPath reports whether path is the default WARP config path for
// a given Tailscale state directory. It is not used by the warp package
// itself; it exists so callers can agree on a single location.
func IsWARPConfigPath(baseDir string) string {
	if baseDir == "" {
		return ""
	}
	return baseDir + string(os.PathSeparator) + "warp-client.json"
}
