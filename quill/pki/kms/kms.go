// Package kms provides an abstraction over cloud KMS / HSM signing backends.
//
// A KMS-backed signer implements stdlib crypto.Signer so it can drop into the
// existing CMS signing path without changes — the private key never leaves the
// HSM and quill only ever sees the resulting signature bytes.
package kms

import (
	"context"
	"crypto"
	"fmt"
	"io"
	"strings"
	"sync"
)

// Signer is a KMS-backed signer. It satisfies crypto.Signer so it slots into
// existing signing paths (CMS, x509.CreateCertificateRequest, etc.) unchanged.
type Signer interface {
	crypto.Signer
	io.Closer

	// KeyID returns a stable identifier for the underlying key (e.g. an ARN
	// or alias) suitable for logging and diagnostics.
	KeyID() string
}

// Provider knows how to open a Signer from a URI of its scheme.
type Provider interface {
	// Scheme returns the URI scheme this provider handles, e.g. "awskms".
	Scheme() string

	// Open establishes a session to the underlying KMS service and returns a
	// ready-to-use Signer. The provider is responsible for fetching the public
	// key so callers can verify cert/key matches without an extra round trip.
	Open(ctx context.Context, uri string) (Signer, error)
}

var (
	registryMu sync.RWMutex
	registry   = map[string]Provider{}
)

// Register makes a provider available under its scheme. Intended to be called
// from a provider package's init() so consumers opt in by blank-importing.
func Register(p Provider) {
	registryMu.Lock()
	defer registryMu.Unlock()
	registry[p.Scheme()] = p
}

// Open dispatches to the registered provider for the URI's scheme.
func Open(ctx context.Context, uri string) (Signer, error) {
	scheme, _, ok := strings.Cut(uri, ":")
	if !ok || scheme == "" {
		return nil, fmt.Errorf("kms uri missing scheme: %q", uri)
	}

	registryMu.RLock()
	p, found := registry[scheme]
	registryMu.RUnlock()

	if !found {
		return nil, fmt.Errorf("no kms provider registered for scheme %q (did you blank-import the provider package?)", scheme)
	}
	return p.Open(ctx, uri)
}

// Schemes returns the list of registered scheme names. Intended for help text
// and diagnostics.
func Schemes() []string {
	registryMu.RLock()
	defer registryMu.RUnlock()
	out := make([]string, 0, len(registry))
	for s := range registry {
		out = append(out, s)
	}
	return out
}
