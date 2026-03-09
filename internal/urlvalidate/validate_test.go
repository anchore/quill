package urlvalidate

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// defaultValidator creates a validator with default production config for testing.
func defaultValidator() *Validator {
	return New(DefaultConfig())
}

func TestValidate(t *testing.T) {
	v := defaultValidator()

	tests := []struct {
		name        string
		url         string
		wantWarning bool
		wantErr     require.ErrorAssertionFunc
	}{
		// tier 1: allowlisted domains (no warning, no error)
		{
			name: "valid apple.com URL",
			url:  "https://apple.com/logs/12345",
		},
		{
			name: "valid developer.apple.com URL",
			url:  "https://developer.apple.com/logs/12345",
		},
		{
			name: "valid cdn.notary.apple.com URL",
			url:  "https://cdn.notary.apple.com/logs/12345.json",
		},
		{
			name: "valid URL with query params",
			url:  "https://notary.apple.com/logs?id=12345&format=json",
		},
		{
			name: "valid URL with port",
			url:  "https://developer.apple.com:443/logs/12345",
		},
		{
			name: "valid www.apple.com URL",
			url:  "https://www.apple.com/certificateauthority/",
		},
		{
			name: "valid Apple notary S3 bucket URL",
			url:  "https://notary-artifacts-prod.s3.amazonaws.com/prod/abc123/developer_log.json?X-Amz-Security-Token=xyz",
		},

		// tier 2: denylisted hosts (error)
		{
			name:    "localhost rejected",
			url:     "https://localhost/admin",
			wantErr: require.Error,
		},
		{
			name:    "sub.localhost rejected",
			url:     "https://sub.localhost/admin",
			wantErr: require.Error,
		},
		{
			name:    "127.0.0.1 rejected",
			url:     "https://127.0.0.1/admin",
			wantErr: require.Error,
		},
		{
			name:    "AWS metadata endpoint rejected",
			url:     "https://169.254.169.254/latest/meta-data",
			wantErr: require.Error,
		},
		{
			name:    "IPv6 localhost rejected",
			url:     "https://[::1]/admin",
			wantErr: require.Error,
		},
		{
			name:    "internal IP 192.168.x rejected",
			url:     "https://192.168.1.1/admin",
			wantErr: require.Error,
		},
		{
			name:    "internal IP 10.x rejected",
			url:     "https://10.0.0.1/admin",
			wantErr: require.Error,
		},
		{
			name:    "internal IP 172.16.x rejected",
			url:     "https://172.16.0.1/admin",
			wantErr: require.Error,
		},
		{
			name:    "public IP also rejected",
			url:     "https://8.8.8.8/dns",
			wantErr: require.Error,
		},

		// tier 3: unknown domains (allowed with warning)
		{
			name:        "unknown domain allowed with warning",
			url:         "https://example.com/logs",
			wantWarning: true,
		},
		{
			name:        "other S3 bucket allowed with warning",
			url:         "https://other-bucket.s3.amazonaws.com/data",
			wantWarning: true,
		},
		{
			name:        "S3 regional bucket allowed with warning",
			url:         "https://bucket.s3.us-east-1.amazonaws.com/data",
			wantWarning: true,
		},
		{
			name:        "random CDN allowed with warning",
			url:         "https://cdn.example.com/logs/12345",
			wantWarning: true,
		},

		// invalid scheme (error regardless of host)
		{
			name:    "http scheme rejected",
			url:     "http://apple.com/logs/12345",
			wantErr: require.Error,
		},
		{
			name:    "ftp scheme rejected",
			url:     "ftp://apple.com/logs/12345",
			wantErr: require.Error,
		},
		{
			name:    "file scheme rejected",
			url:     "file:///etc/passwd",
			wantErr: require.Error,
		},
		{
			name:    "javascript scheme rejected",
			url:     "javascript:alert(1)",
			wantErr: require.Error,
		},
		{
			name:    "data scheme rejected",
			url:     "data:text/html,<script>alert(1)</script>",
			wantErr: require.Error,
		},

		// IPv4-mapped IPv6 addresses (should be denied)
		{
			name:    "IPv4-mapped loopback rejected",
			url:     "https://[::ffff:127.0.0.1]/admin",
			wantErr: require.Error,
		},
		{
			name:    "IPv4-mapped metadata endpoint rejected",
			url:     "https://[::ffff:169.254.169.254]/latest/meta-data",
			wantErr: require.Error,
		},
		{
			name:    "IPv4-mapped private IP rejected",
			url:     "https://[::ffff:192.168.1.1]/admin",
			wantErr: require.Error,
		},

		// octal/hex IP notation (Go's net.ParseIP doesn't parse these, so they're
		// treated as domain names and allowed with warning - they'd fail DNS anyway)
		{
			name:        "octal IP notation allowed with warning (not parsed as IP)",
			url:         "https://0177.0.0.1/admin",
			wantWarning: true,
		},
		{
			name:        "hex IP notation allowed with warning (not parsed as IP)",
			url:         "https://0x7f.0.0.1/admin",
			wantWarning: true,
		},

		// SSRF bypass attempts (should be denied or warned)
		{
			name:        "userinfo attack: apple.com@evil.com correctly identifies evil.com as host",
			url:         "https://apple.com@evil.com/logs",
			wantWarning: true, // evil.com is the actual host, allowed with warning
		},
		{
			name:        "apple.com.evil.com allowed with warning (not actually apple)",
			url:         "https://apple.com.evil.com/logs",
			wantWarning: true,
		},
		{
			name:        "evilapple.com allowed with warning",
			url:         "https://evilapple.com/logs",
			wantWarning: true,
		},
		{
			name:        "similar domain allowed with warning (apple.com.attacker.com)",
			url:         "https://apple.com.attacker.com/logs",
			wantWarning: true,
		},

		// edge cases (error)
		{
			name:    "empty URL rejected",
			url:     "",
			wantErr: require.Error,
		},
		{
			name:    "URL with no hostname rejected",
			url:     "https:///path",
			wantErr: require.Error,
		},
		{
			name:    "malformed URL rejected",
			url:     "://invalid",
			wantErr: require.Error,
		},
		{
			name:    "completely invalid URL rejected",
			url:     "not-a-url",
			wantErr: require.Error,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.wantErr == nil {
				tt.wantErr = require.NoError
			}

			warning, err := v.Validate(tt.url)
			tt.wantErr(t, err)

			if err != nil {
				return
			}

			if tt.wantWarning {
				assert.NotEmpty(t, warning, "expected a warning for unknown host")
				assert.Contains(t, warning, "unexpected host")
			} else {
				assert.Empty(t, warning, "expected no warning for trusted host")
			}
		})
	}
}

func TestValidate_CustomDomains(t *testing.T) {
	// create a validator with an additional trusted domain
	cfg := DefaultConfig()
	cfg.TrustedDomains = append(cfg.TrustedDomains, "test.local")
	v := New(cfg)

	// now test.local should be allowed without warning
	warning, err := v.Validate("https://test.local/logs")
	require.NoError(t, err)
	assert.Empty(t, warning)

	// but other untrusted domains should still warn
	warning, err = v.Validate("https://other.local/logs")
	require.NoError(t, err)
	assert.NotEmpty(t, warning)

	// and IPs should still be denied
	_, err = v.Validate("https://127.0.0.1/logs")
	require.Error(t, err)
}

func TestIsDeniedHost(t *testing.T) {
	tests := []struct {
		name       string
		host       string
		wantDenied bool
	}{
		// loopback
		{name: "localhost", host: "localhost", wantDenied: true},
		{name: "sub.localhost", host: "sub.localhost", wantDenied: true},
		{name: "127.0.0.1", host: "127.0.0.1", wantDenied: true},
		{name: "127.0.0.2", host: "127.0.0.2", wantDenied: true},
		{name: "::1", host: "::1", wantDenied: true},

		// private ranges
		{name: "10.0.0.1", host: "10.0.0.1", wantDenied: true},
		{name: "10.255.255.255", host: "10.255.255.255", wantDenied: true},
		{name: "172.16.0.1", host: "172.16.0.1", wantDenied: true},
		{name: "172.31.255.255", host: "172.31.255.255", wantDenied: true},
		{name: "192.168.0.1", host: "192.168.0.1", wantDenied: true},
		{name: "192.168.255.255", host: "192.168.255.255", wantDenied: true},

		// link-local (cloud metadata)
		{name: "169.254.169.254", host: "169.254.169.254", wantDenied: true},
		{name: "169.254.0.1", host: "169.254.0.1", wantDenied: true},

		// IPv4-mapped IPv6 addresses
		{name: "::ffff:127.0.0.1", host: "::ffff:127.0.0.1", wantDenied: true},
		{name: "::ffff:10.0.0.1", host: "::ffff:10.0.0.1", wantDenied: true},
		{name: "::ffff:192.168.1.1", host: "::ffff:192.168.1.1", wantDenied: true},
		{name: "::ffff:169.254.169.254", host: "::ffff:169.254.169.254", wantDenied: true},

		// public IPs (also denied - we only want domain names)
		{name: "8.8.8.8", host: "8.8.8.8", wantDenied: true},
		{name: "1.1.1.1", host: "1.1.1.1", wantDenied: true},

		// domain names (not denied by isDeniedHost)
		{name: "example.com", host: "example.com", wantDenied: false},
		{name: "apple.com", host: "apple.com", wantDenied: false},
		{name: "s3.amazonaws.com", host: "s3.amazonaws.com", wantDenied: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reason := isDeniedHost(tt.host)
			if tt.wantDenied {
				assert.NotEmpty(t, reason, "expected host to be denied")
			} else {
				assert.Empty(t, reason, "expected host to not be denied")
			}
		})
	}
}
