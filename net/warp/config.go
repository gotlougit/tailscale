// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

// Package warp implements a Cloudflare WARP client: registration with
// Cloudflare's WARP service and a MASQUE (HTTP/3 CONNECT) tunnel to
// Cloudflare's edge through which TCP and UDP traffic can be proxied.
package warp

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"

	"tailscale.com/atomicfile"
)

// Config is the persisted registration state for a WARP device. It mirrors
// what the WARP registration API returns after the two-step
// (curve25519/wireguard -> secp256r1/masque) registration flow.
type Config struct {
	// PrivateKey is the base64 encoding of the PKCS#8/DER ECDSA P-256
	// private key enrolled with Cloudflare. It is used as the client
	// certificate key for the mTLS handshake with the edge.
	PrivateKey string `json:"private_key"`
	// EndpointV4 is the edge's IPv4 address (e.g. "162.159.198.2").
	EndpointV4 string `json:"endpoint_v4"`
	// EndpointV6 is the edge's IPv6 address, if any.
	EndpointV6 string `json:"endpoint_v6"`
	// EndpointPort is the edge's UDP port (usually 443). If zero, 443 is
	// used.
	EndpointPort int `json:"endpoint_port,omitempty"`
	// EndpointPubKey is the PEM-encoded ECDSA public key of the edge,
	// used to pin the TLS certificate presented by the edge.
	EndpointPubKey string `json:"endpoint_pub_key"`
	// ID is the registration id, used for account PATCH requests.
	ID string `json:"id"`
	// AccessToken is the bearer token authorizing account operations.
	AccessToken string `json:"access_token"`
	// IPv4 is the IPv4 address Cloudflare assigned to this device.
	IPv4 string `json:"ipv4"`
	// IPv6 is the IPv6 address Cloudflare assigned to this device.
	IPv6 string `json:"ipv6"`
}

// Load loads the configuration from path.
func (c *Config) Load(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(data, c); err != nil {
		return fmt.Errorf("warp: parse config %s: %w", path, err)
	}
	return nil
}

// Save writes the configuration to path atomically with 0600 permissions.
// It creates a temporary file and renames it, so a crash mid-write won't
// leave a partially-written config that Load would silently accept.
func (c *Config) Save(path string) error {
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	return atomicfile.WriteFile(path, data, 0o600)
}

// Valid reports whether the config holds a complete, usable registration
// (private key, pinned edge public key, access token, edge endpoint, and
// assigned tunnel address). A file that parses as JSON but is missing any of
// these is treated as "no valid registration" and must be re-registered.
func (c *Config) Valid() bool {
	return c.PrivateKey != "" &&
		c.EndpointPubKey != "" &&
		c.AccessToken != "" &&
		(c.EndpointV4 != "" || c.EndpointV6 != "") &&
		(c.IPv4 != "" || c.IPv6 != "")
}

// ecPrivateKey returns the enrolled P-256 private key used for the mTLS
// client certificate on the QUIC connection.
func (c *Config) ecPrivateKey() (*ecdsa.PrivateKey, error) {
	der, err := base64.StdEncoding.DecodeString(c.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("warp: decode private key: %w", err)
	}
	if k, err := x509.ParseECPrivateKey(der); err == nil {
		return k, nil
	}
	// Fall back to PKCS#8 encoding.
	k, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		return nil, fmt.Errorf("warp: parse private key: %w", err)
	}
	ec, ok := k.(*ecdsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("warp: private key is not ECDSA")
	}
	return ec, nil
}

// ecEndpointPublicKey parses the PEM-encoded, pinned edge public key.
func (c *Config) ecEndpointPublicKey() (*ecdsa.PublicKey, error) {
	block, _ := pem.Decode([]byte(c.EndpointPubKey))
	if block == nil {
		return nil, fmt.Errorf("warp: no PEM block in endpoint public key")
	}
	pk, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("warp: parse endpoint public key: %w", err)
	}
	ec, ok := pk.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("warp: endpoint public key is not ECDSA")
	}
	return ec, nil
}
