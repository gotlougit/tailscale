// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package warp

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"tailscale.com/envknob"
	"tailscale.com/types/logger"
)

const (
	// apiBase is the Cloudflare WARP registration API base URL.
	apiBase = "https://api.cloudflareclient.com"
	// tosMarker is the value sent in the "tos" registration field. Cloudflare's
	// API only checks for the presence of a non-empty value; the official
	// clients send "Authorization for these Terms and Conditions".
	tosMarker = "Authorization for these Terms and Conditions"
)

var (
	// apiVersion and clientVersion are the WARP *mobile* consumer registration
	// API tags ("v0a4471" == "v0" + "a"[ndroid] + build "4471";
	// CF-Client-Version "a-6.35-4471"). The edge does not strictly validate
	// the suffix (verified: arbitrary "v0a<digits>" is accepted with a 200),
	// so these are best-effort identifiers, overridable for testing.
	apiVersion = func() string {
		if v := envknob.String("WARP_API_VERSION"); v != "" {
			return v
		}
		return "v0a4471"
	}
	clientVer = func() string {
		if v := envknob.String("WARP_CLIENT_VERSION"); v != "" {
			return v
		}
		return "a-6.35-4471"
	}
	wgKeyType    = "curve25519"
	wgTunType    = "wireguard"
	mqKeyType    = "secp256r1"
	mqTunType    = "masque"
	endpointPort = 443
)

// Registration is the set of values exchanged with Cloudflare during
// registration. Modeled on the WARP registration API.
type registrationRequest struct {
	Key       string `json:"key"`
	InstallID string `json:"install_id"`
	FcmToken  string `json:"fcm_token"`
	Tos       string `json:"tos"`
	Model     string `json:"model"`
	Serial    string `json:"serial_number"`
	OsVersion string `json:"os_version"`
	KeyType   string `json:"key_type"`
	TunType   string `json:"tunnel_type"`
	Locale    string `json:"locale"`
}

type accountData struct {
	ID     string `json:"id"`
	Token  string `json:"token"`
	Key    string `json:"key"`
	Config struct {
		ClientID string `json:"client_id"`
		Peers    []struct {
			PublicKey string `json:"public_key"`
			Endpoint  struct {
				V4    string `json:"v4"`
				V6    string `json:"v6"`
				Host  string `json:"host"`
				Ports []int  `json:"ports"`
			} `json:"endpoint"`
		} `json:"peers"`
		Interface struct {
			Addresses struct {
				V4 string `json:"v4"`
				V6 string `json:"v6"`
			} `json:"addresses"`
		} `json:"interface"`
	} `json:"config"`
}

type deviceUpdate struct {
	Key     string `json:"key"`
	KeyType string `json:"key_type"`
	TunType string `json:"tunnel_type"`
	Name    string `json:"name,omitempty"`
}

// Register performs the two-step WARP registration:
//
//  1. POST /reg with a random curve25519 key (tunnel_type=wireguard),
//     creating the account and returning id + access token.
//  2. PATCH /reg/{id} with an EC P-256 key (tunnel_type=masque), enrolling
//     the key that will be used for the mTLS handshake with the edge, and
//     returning the edge endpoint + pinned edge public key.
//
// The account must end in secp256r1/masque for the QUIC/HTTP3 edge to engage.
//
// Registering a device implies acceptance of Cloudflare's WARP Terms of
// Service; the caller is expected to have confirmed that.
func Register(ctx context.Context, logf logger.Logf) (*Config, error) {
	return RegisterWithOptions(ctx, logf, RegisterOptions{})
}

// RegisterOptions adjust the behavior of Register. It exists for testing.
type RegisterOptions struct {
	// BaseURL overrides the Cloudflare registration API base URL.
	BaseURL string
}

// RegisterWithOptions is Register with explicit options.
func RegisterWithOptions(ctx context.Context, logf logger.Logf, opts RegisterOptions) (*Config, error) {
	base := opts.BaseURL
	if base == "" {
		base = apiBase
	}
	logf = logger.WithPrefix(logf, "warp: ")
	// Step 1: register with a random Curve25519 public key (any 32 bytes).
	wgKey, err := randomBytes(32)
	if err != nil {
		return nil, err
	}
	serial, err := randomHex(8)
	if err != nil {
		return nil, err
	}
	reg := registrationRequest{
		Key:     base64.StdEncoding.EncodeToString(wgKey),
		Tos:     time.Now().Format("2006-01-02T15:04:05.000-07:00"),
		Model:   "PC",
		Serial:  serial,
		KeyType: wgKeyType,
		TunType: wgTunType,
		Locale:  "en_US",
	}
	regBody, err := json.Marshal(reg)
	if err != nil {
		return nil, err
	}

	logf("registering with Cloudflare WARP (step 1/2)")
	step1, err := doAPI(ctx, http.MethodPost, base+"/"+apiVersion()+"/reg", "", regBody)
	if err != nil {
		return nil, fmt.Errorf("warp: registration step 1: %w", err)
	}
	var acc accountData
	if err := json.Unmarshal(step1, &acc); err != nil {
		return nil, fmt.Errorf("warp: registration step 1 decode: %w", err)
	}
	if acc.ID == "" || acc.Token == "" {
		return nil, fmt.Errorf("warp: registration step 1: missing id or token in response")
	}

	// Generate the P-256 keypair that will be enrolled for MASQUE mTLS.
	ecPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	// Store as PKCS#8 DER (compatible with both EC and PKCS#8 parsing).
	privDER, err := x509.MarshalPKCS8PrivateKey(ecPriv)
	if err != nil {
		return nil, err
	}
	pubDER, err := x509.MarshalPKIXPublicKey(&ecPriv.PublicKey)
	if err != nil {
		return nil, err
	}

	// Step 2: PATCH the account to switch to secp256r1 + masque.
	upd := deviceUpdate{
		Key:     base64.StdEncoding.EncodeToString(pubDER),
		KeyType: mqKeyType,
		TunType: mqTunType,
		Name:    "tailscale-warp",
	}
	updBody, err := json.Marshal(upd)
	if err != nil {
		return nil, err
	}

	logf("enrolling MASQUE key with Cloudflare WARP (step 2/2)")
	step2, err := doAPI(ctx, http.MethodPatch, base+"/"+apiVersion()+"/reg/"+acc.ID, acc.Token, updBody)
	if err != nil {
		return nil, fmt.Errorf("warp: registration step 2: %w", err)
	}
	var acc2 accountData
	if err := json.Unmarshal(step2, &acc2); err != nil {
		return nil, fmt.Errorf("warp: registration step 2 decode: %w", err)
	}
	if len(acc2.Config.Peers) == 0 {
		return nil, fmt.Errorf("warp: registration step 2: no peers in response")
	}

	peer := acc2.Config.Peers[0]
	port := 443
	if len(peer.Endpoint.Ports) > 0 && peer.Endpoint.Ports[0] != 0 {
		port = peer.Endpoint.Ports[0]
	}
	cfg := &Config{
		PrivateKey:     base64.StdEncoding.EncodeToString(privDER),
		EndpointV4:     stripPort(peer.Endpoint.V4),
		EndpointV6:     stripPort(peer.Endpoint.V6),
		EndpointPort:   port,
		EndpointPubKey: peer.PublicKey,
		ID:             acc2.ID,
		AccessToken:    acc.Token,
		IPv4:           acc2.Config.Interface.Addresses.V4,
		IPv6:           acc2.Config.Interface.Addresses.V6,
	}
	logf("registered WARP device %s (edge %s)", acc2.ID, stripPort(peer.Endpoint.V4))
	return cfg, nil
}

// doAPI performs an HTTP request against the WARP API. The request context
// is used for the lifetime of the request only.
func doAPI(ctx context.Context, method, url, token string, body []byte) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, method, url, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "WARP for Android")
	req.Header.Set("CF-Client-Version", clientVer())
	req.Header.Set("Content-Type", "application/json; charset=UTF-8")
	req.Header.Set("Connection", "Keep-Alive")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("api %s %s -> %s: %s", method, url, resp.Status, truncate(string(data), 300))
	}
	return data, nil
}

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n] + "..."
	}
	return s
}

// randomBytes returns n cryptographically random bytes.
func randomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	_, err := rand.Read(b)
	return b, err
}

// randomHex returns n cryptographically random bytes as a hex string.
func randomHex(n int) (string, error) {
	b, err := randomBytes(n)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// stripPort removes a trailing ":N" or "[v6]:N" from an endpoint string.
func stripPort(addr string) string {
	if len(addr) == 0 {
		return addr
	}
	if addr[0] == '[' { // [v6]:port
		for i := 1; i < len(addr); i++ {
			if addr[i] == ']' {
				return addr[:i+1]
			}
		}
		return addr
	}
	if addr[len(addr)-1] == ']' {
		return addr
	}
	for i := len(addr) - 1; i >= 0; i-- {
		if addr[i] == ':' {
			return addr[:i]
		}
	}
	return addr
}