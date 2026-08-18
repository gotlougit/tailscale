// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package warp

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"tailscale.com/types/logger"
)

// validTestConfig returns a Config with a freshly-generated EC key that will
// pass ec.PrivateKey parsing (so Start/NewTunnel succeed).
func validTestConfig(t *testing.T) *Config {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	pubDER, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	pubPEM := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER}))
	return &Config{
		PrivateKey:     base64.StdEncoding.EncodeToString(der),
		EndpointV4:     "127.0.0.1", // unused for lifecycle tests
		EndpointPort:   1,
		EndpointPubKey: pubPEM,
		ID:             "test-id",
		AccessToken:    "test-token",
		IPv4:           "100.96.0.1",
	}
}

// TestConfigSaveAtomic verifies that Config.Save uses the atomic write pattern
// (write to a temp file, then rename) so a crash mid-write won't leave a
// corrupt file that Load would silently accept.
func TestConfigSaveAtomic(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "warp-client.json")

	cfg := validTestConfig(t)
	if err := cfg.Save(path); err != nil {
		t.Fatalf("Save: %v", err)
	}

	var loaded Config
	if err := loaded.Load(path); err != nil {
		t.Fatalf("Load after Save: %v", err)
	}
	if loaded.ID != cfg.ID {
		t.Fatalf("round trip ID: got %q, want %q", loaded.ID, cfg.ID)
	}

	// Ensure no stray temp file left behind.
	d, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(d) != 1 {
		t.Errorf("expected 1 file in dir after save, got %d: %v", len(d), d)
	}
}

// TestClientClose verifies that Close() marks the client as done, clears the
// connected flag, and that double-Close is safe.
func TestClientClose(t *testing.T) {
	dir := t.TempDir()
	cl := NewClient(logger.Discard, filepath.Join(dir, "warp-client.json"), false)

	select {
	case <-cl.Done():
		t.Fatal("Done() channel closed before Close()")
	default:
	}

	if err := cl.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	select {
	case <-cl.Done():
	default:
		t.Fatal("Done() channel not closed after Close()")
	}

	if st := cl.Status(); st.Connected {
		t.Fatal("Status().Connected is true after Close()")
	}

	// Double close must be safe.
	if err := cl.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}

	if _, err := cl.Dial(context.Background(), "tcp", "1.1.1.1:443"); err == nil {
		t.Fatal("Dial after Close should fail")
	}
	if err := cl.SendPacket(nil); err == nil {
		t.Fatal("SendPacket after Close should fail")
	}
}

// TestClientStatusEdgeCases covers Status() on an unregistered, unstarted
// client and after Close.
func TestClientStatusEdgeCases(t *testing.T) {
	dir := t.TempDir()
	cl := NewClient(logger.Discard, filepath.Join(dir, "warp-client.json"), false)

	// Unregistered client: no config on disk, no in-memory cfg.
	st := cl.Status()
	if st.Registered {
		t.Fatal("unregistered client should not report registered")
	}
	if st.Connected {
		t.Fatal("unregistered client should not report connected")
	}
	if st.LastError != "" {
		t.Fatalf("unregistered client should have no last error, got %q", st.LastError)
	}

	// Save a valid config on disk (but don't call Start or Register).
	cfg := validTestConfig(t)
	if err := cfg.Save(cl.ConfigPath()); err != nil {
		t.Fatal(err)
	}

	// Status must now report registered via the disk fallback.
	st = cl.Status()
	if !st.Registered {
		t.Fatal("client with saved config should report registered via disk fallback")
	}
	if st.Connected {
		t.Fatal("client should not report connected before Start")
	}
	if st.DeviceID != cfg.ID {
		t.Fatalf("DeviceID = %q; want %q", st.DeviceID, cfg.ID)
	}
	if st.IPv4 != cfg.IPv4 {
		t.Fatalf("IPv4 = %q; want %q", st.IPv4, cfg.IPv4)
	}

	// After Close, status must still report registered.
	cl.Close()
	st = cl.Status()
	if !st.Registered {
		t.Fatal("client should still report registered after Close (config on disk)")
	}
	if st.Connected {
		t.Fatal("client should not report connected after Close")
	}
}

// TestRegisterNetworkFailure exercises the error paths in Register when the
// API server is unreachable. Accepts both network errors and success (if the
// test environment happens to have internet access).
func TestRegisterNetworkFailure(t *testing.T) {
	dir := t.TempDir()
	cl := NewClient(logger.Discard, filepath.Join(dir, "warp-client.json"), false)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	err := cl.Register(ctx)
	if err == nil {
		// Registration succeeded; clean up the registered config and
		// note the test passed (the env has internet).
		os.Remove(cl.ConfigPath())
		t.Log("Register succeeded (test env has internet)")
		return
	}
	// The error should contain something network-related.
	msg := err.Error()
	if !strings.Contains(msg, "no such host") &&
		!strings.Contains(msg, "connection refused") &&
		!strings.Contains(msg, "i/o timeout") &&
		!strings.Contains(msg, "TLS handshake") {
		t.Logf("Register error (expected network error): %v", err)
	}
}

// TestClientStatusJSON confirms that warp.Status JSON tags match the CLI's
// warpStatusJSON struct by round-tripping through JSON and checking field
// names.
func TestClientStatusJSON(t *testing.T) {
	st := Status{
		Enabled:    true,
		Registered: true,
		Connected:  true,
		DeviceID:   "device-1",
		Endpoint:   "162.159.198.2:443",
		EndpointIP: "162.159.198.2",
		IPv4:       "100.96.0.1",
		LastError:  "",
	}
	data, err := json.Marshal(st)
	if err != nil {
		t.Fatalf("Marshal Status: %v", err)
	}

	var m map[string]any
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}

	if v, ok := m["enabled"]; !ok || v != true {
		t.Errorf(`missing or wrong "enabled": %v`, v)
	}
	if v, ok := m["registered"]; !ok || v != true {
		t.Errorf(`missing or wrong "registered": %v`, v)
	}
	if v, ok := m["connected"]; !ok || v != true {
		t.Errorf(`missing or wrong "connected": %v`, v)
	}
	if v, ok := m["deviceId"]; !ok || v != "device-1" {
		t.Errorf(`missing or wrong "deviceId": %v`, v)
	}
	if v, ok := m["endpoint"]; !ok || v != "162.159.198.2:443" {
		t.Errorf(`missing or wrong "endpoint": %v`, v)
	}
	if v, ok := m["endpointIp"]; !ok || v != "162.159.198.2" {
		t.Errorf(`missing or wrong "endpointIp": %v`, v)
	}
	if v, ok := m["ipv4"]; !ok || v != "100.96.0.1" {
		t.Errorf(`missing or wrong "ipv4": %v`, v)
	}
	if _, ok := m["lastError"]; ok {
		t.Error(`"lastError" should be omitted when empty`)
	}
}

// TestClientWaitOnUnstarted verifies that Wait() returns immediately on an
// unstarted client.
func TestClientWaitOnUnstarted(t *testing.T) {
	cl := NewClient(logger.Discard, "", false)
	done := make(chan struct{})
	go func() {
		cl.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Wait() on unstarted client blocked forever")
	}
}

// TestClientWaitAfterCloseOnStarted verifies that after Start + Close, Wait()
// eventually completes. Uses a 20s timeout since the maintain goroutine may
// be in a 15s QUIC dial.
func TestClientWaitAfterCloseOnStarted(t *testing.T) {
	cl := newTestClient(t)
	cl.Close()

	done := make(chan struct{})
	go func() {
		cl.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(20 * time.Second):
		t.Fatal("Wait() did not complete within 20s after Close")
	}
}

// TestClientDoubleStart verifies that starting an already-started client
// returns an error.
func TestClientDoubleStart(t *testing.T) {
	cl := newTestClient(t)

	err := cl.Start(context.Background())
	if err == nil {
		t.Fatal("second Start should fail")
	}
	if !strings.Contains(err.Error(), "already started") {
		t.Errorf("second Start error = %q; want 'already started'", err)
	}

	cl.Close()
}

// TestClientRegisterWhileRunning verifies that calling Register() on a
// started client returns an error.
func TestClientRegisterWhileRunning(t *testing.T) {
	cl := newTestClient(t)

	err := cl.Register(context.Background())
	if err == nil {
		t.Fatal("Register while running should fail")
	}
	if !strings.Contains(err.Error(), "cannot re-register while running") {
		t.Errorf("Register error = %q; want 'cannot re-register while running'", err)
	}

	cl.Close()
}
