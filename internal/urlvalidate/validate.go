// Package urlvalidate provides URL validation for Apple notarization service responses.
//
// The developerLogUrl field comes from appstoreconnect.apple.com over HTTPS. Intercepting
// this response requires a compromised CA or TLS inspection proxy. The main risk we guard
// against is requests to internal services (localhost, private IPs) and cloud metadata
// endpoints (169.254.169.254).
//
// We use a three-tier validation approach:
//   - Known domains (apple.com, Apple's S3 bucket): allowed
//   - IPs and localhost: blocked
//   - Unknown domains: allowed with a warning logged
//
// This allows quill to keep working if Apple changes their infrastructure (e.g., new S3
// bucket, new CDN) while alerting users to investigate.
//
// We chose domain validation over certificate validation because:
//   - Domain checks happen before any connection; cert checks require connecting first
//   - Apple serves logs from S3, which has Amazon certificates, not Apple certificates
//   - Certificate pinning is brittle (Chrome removed HPKP for this reason)
//   - Certificate org fields are not reliable (anyone can register "Apple LLC")
package urlvalidate

import (
	"fmt"
	"net"
	"net/url"
	"slices"
	"strings"
)

// Config holds the configuration for URL validation.
type Config struct {
	TrustedDomains []string
	AllowedSchemes []string
}

// DefaultConfig returns the default configuration for production use.
func DefaultConfig() Config {
	return Config{
		TrustedDomains: []string{
			".apple.com",
			// Apple's notary v2 API returns pre-signed S3 URLs for developer logs
			"notary-artifacts-prod.s3.amazonaws.com",
		},
		AllowedSchemes: []string{"https"},
	}
}

// Validator validates URLs for fetching Apple resources.
type Validator struct {
	config Config
}

// New creates a new Validator with the given configuration.
func New(cfg Config) *Validator {
	return &Validator{config: cfg}
}

// Validate validates a URL for fetching Apple resources using a three-tier approach:
//  1. allowlist: Known trusted domains (apple.com, Apple's S3 bucket) - allowed silently
//  2. denylist: Known dangerous targets (IPs, localhost, metadata endpoints) - rejected with error
//  3. unknown: Other domains - allowed but returns a warning message for logging
//
// Returns:
//   - warning: non-empty if the URL is allowed but from an unexpected host (should be logged)
//   - error: non-nil if the URL is denied (should not be fetched)
func (v *Validator) Validate(rawURL string) (warning string, err error) {
	if rawURL == "" {
		return "", fmt.Errorf("URL is empty")
	}

	parsed, err := url.Parse(rawURL)
	if err != nil {
		return "", fmt.Errorf("invalid URL: %w", err)
	}

	// require allowed scheme (https in production, http can be added for tests)
	schemeAllowed := slices.Contains(v.config.AllowedSchemes, parsed.Scheme)
	if !schemeAllowed {
		return "", fmt.Errorf("URL scheme must be https, got %q", parsed.Scheme)
	}

	// url.Hostname() properly extracts the host, handling ports and IPv6 addresses.
	host := strings.ToLower(parsed.Hostname())
	if host == "" {
		return "", fmt.Errorf("URL has no hostname")
	}

	// tier 1: check allowlist (known trusted domains)
	if v.isTrustedDomain(host) {
		return "", nil
	}

	// tier 2: check denylist (dangerous targets)
	if reason := isDeniedHost(host); reason != "" {
		return "", fmt.Errorf("URL host %q is not allowed: %s", host, reason)
	}

	// tier 3: unknown domain - allow but warn
	return fmt.Sprintf("unexpected host %q for developer log URL; this may indicate Apple has changed their infrastructure or a potential security issue", host), nil
}

// isTrustedDomain checks if the host matches any trusted domain pattern.
func (v *Validator) isTrustedDomain(host string) bool {
	for _, domain := range v.config.TrustedDomains {
		baseDomain := strings.TrimPrefix(domain, ".")
		// allow exact match (e.g., "apple.com") or subdomain match (e.g., "developer.apple.com")
		if host == baseDomain || strings.HasSuffix(host, domain) {
			return true
		}
	}
	return false
}

// isDeniedHost checks if the host is a known dangerous target.
// Returns a reason string if denied, empty string if not denied.
func isDeniedHost(host string) string {
	// check for IP addresses (all IPs are denied to prevent SSRF to internal services)
	if ip := net.ParseIP(host); ip != nil {
		if isLoopback(ip) {
			return "loopback addresses are not allowed"
		}
		if isPrivate(ip) {
			return "private network addresses are not allowed"
		}
		if isLinkLocal(ip) {
			return "link-local addresses are not allowed (includes cloud metadata endpoints)"
		}
		// deny all other IPs as well - legitimate services use domain names
		return "IP addresses are not allowed; expected a domain name"
	}

	// check for localhost variations
	if host == "localhost" || strings.HasSuffix(host, ".localhost") {
		return "localhost is not allowed"
	}

	return ""
}

func isLoopback(ip net.IP) bool {
	return ip.IsLoopback()
}

func isPrivate(ip net.IP) bool {
	return ip.IsPrivate()
}

func isLinkLocal(ip net.IP) bool {
	// covers IPv4 link-local (169.254.x.x) which includes AWS/cloud metadata (169.254.169.254)
	// and IPv6 link-local (fe80::/10)
	return ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast()
}
