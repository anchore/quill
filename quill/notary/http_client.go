package notary

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/anchore/quill/internal/log"
	"github.com/anchore/quill/internal/urlvalidate"
)

type httpClient struct {
	client    *http.Client
	token     string
	validator *urlvalidate.Validator
}

func newHTTPClient(token string, httpTimeout time.Duration, validator *urlvalidate.Validator) *httpClient {
	if httpTimeout == 0 {
		httpTimeout = time.Second * 30
	}

	return &httpClient{
		client: &http.Client{
			Timeout: httpTimeout,
			// validate redirects to prevent SSRF attacks
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				warning, err := validator.Validate(req.URL.String())
				if err != nil {
					return fmt.Errorf("redirect to untrusted URL: %w", err)
				}
				if warning != "" {
					log.Warnf("redirect to %s", warning)
				}
				if len(via) >= 10 {
					return fmt.Errorf("too many redirects")
				}
				return nil
			},
		},
		token:     token,
		validator: validator,
	}
}

// getUnauthenticated fetches a URL without the authorization header.
// Used for pre-signed URLs (like S3) that have their own auth mechanism.
func (s httpClient) getUnauthenticated(ctx context.Context, endpoint string) (*http.Response, error) {
	// validate URL to prevent SSRF attacks
	warning, err := s.validator.Validate(endpoint)
	if err != nil {
		return nil, fmt.Errorf("URL validation failed: %w", err)
	}
	if warning != "" {
		log.Warn(warning)
	}

	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}

	log.Tracef("http %s %s (unauthenticated)", request.Method, request.URL)
	// URL is validated by validator.Validate above
	return s.client.Do(request)
}

func (s httpClient) get(ctx context.Context, endpoint string, body io.Reader) (*http.Response, error) {
	request, err := http.NewRequest(http.MethodGet, endpoint, body)
	if err != nil {
		return nil, err
	}
	request = request.WithContext(ctx)
	return s.do(request)
}

func (s httpClient) post(ctx context.Context, endpoint string, body io.Reader) (*http.Response, error) {
	request, err := http.NewRequest(http.MethodPost, endpoint, body)
	if err != nil {
		return nil, err
	}
	request = request.WithContext(ctx)
	request.Header.Set("Content-Type", "application/json; charset=UTF-8")
	return s.do(request)
}

func (s httpClient) do(request *http.Request) (*http.Response, error) {
	// validate URL to prevent SSRF attacks
	warning, err := s.validator.Validate(request.URL.String())
	if err != nil {
		return nil, fmt.Errorf("URL validation failed: %w", err)
	}
	if warning != "" {
		log.Warn(warning)
	}

	log.Tracef("http %s %s", request.Method, request.URL)
	request.Header.Set("Authorization", fmt.Sprintf("Bearer %s", s.token))
	//nolint:gosec // G704: URL is validated by validator.Validate above
	return s.client.Do(request)
}
