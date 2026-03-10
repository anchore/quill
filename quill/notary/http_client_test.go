package notary

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/quill/internal/urlvalidate"
)

// testValidator creates a validator configured for test servers (allows http and 127.0.0.1).
func testValidator() *urlvalidate.Validator {
	cfg := urlvalidate.DefaultConfig()
	cfg.AllowedSchemes = append(cfg.AllowedSchemes, "http")
	cfg.TrustedDomains = append(cfg.TrustedDomains, "127.0.0.1")
	return urlvalidate.New(cfg)
}

// newTestHTTPClient creates an httpClient configured for test servers (http + 127.0.0.1).
func newTestHTTPClient(token string, timeout time.Duration) *httpClient {
	return newHTTPClient(token, timeout, testValidator())
}

func Test_httpClient_get(t *testing.T) {
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "GET", r.Method)
		return
	}))
	defer s.Close()
	c := newTestHTTPClient("the-token", time.Second*3)

	resp, err := c.get(context.TODO(), s.URL, nil)
	require.NoError(t, err)
	require.Equal(t, "Bearer the-token", resp.Request.Header.Get("Authorization"))
}

func Test_httpClient_post(t *testing.T) {
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "POST", r.Method)
		return
	}))
	defer s.Close()
	c := newTestHTTPClient("the-token", time.Second*3)

	resp, err := c.post(context.TODO(), s.URL, nil)
	require.NoError(t, err)
	require.Equal(t, "application/json; charset=UTF-8", resp.Request.Header.Get("Content-Type"))
	require.Equal(t, "Bearer the-token", resp.Request.Header.Get("Authorization"))
}

func Test_httpClient_getUnauthenticated(t *testing.T) {
	t.Run("follows redirect to allowed host", func(t *testing.T) {
		finalServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte("final response"))
		}))
		defer finalServer.Close()

		redirectServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, finalServer.URL, http.StatusFound)
		}))
		defer redirectServer.Close()

		c := newTestHTTPClient("the-token", time.Second*3)
		resp, err := c.getUnauthenticated(context.TODO(), redirectServer.URL)
		require.NoError(t, err)
		require.Equal(t, http.StatusOK, resp.StatusCode)
	})

	t.Run("blocks redirect to denied host (localhost)", func(t *testing.T) {
		redirectServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// redirect to localhost which is on the denylist
			http.Redirect(w, r, "https://localhost/evil", http.StatusFound)
		}))
		defer redirectServer.Close()

		c := newTestHTTPClient("the-token", time.Second*3)
		_, err := c.getUnauthenticated(context.TODO(), redirectServer.URL)
		require.Error(t, err)
		require.Contains(t, err.Error(), "redirect to untrusted URL")
		require.Contains(t, err.Error(), "localhost")
	})

	t.Run("blocks redirect to denied host (internal IP)", func(t *testing.T) {
		redirectServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// redirect to internal IP which is on the denylist
			http.Redirect(w, r, "https://192.168.1.1/internal", http.StatusFound)
		}))
		defer redirectServer.Close()

		c := newTestHTTPClient("the-token", time.Second*3)
		_, err := c.getUnauthenticated(context.TODO(), redirectServer.URL)
		require.Error(t, err)
		require.Contains(t, err.Error(), "redirect to untrusted URL")
	})

	t.Run("blocks redirect to cloud metadata endpoint", func(t *testing.T) {
		redirectServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// redirect to AWS metadata endpoint
			http.Redirect(w, r, "https://169.254.169.254/latest/meta-data", http.StatusFound)
		}))
		defer redirectServer.Close()

		c := newTestHTTPClient("the-token", time.Second*3)
		_, err := c.getUnauthenticated(context.TODO(), redirectServer.URL)
		require.Error(t, err)
		require.Contains(t, err.Error(), "redirect to untrusted URL")
	})

	t.Run("blocks too many redirects", func(t *testing.T) {
		var redirectCount int
		redirectServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			redirectCount++
			// keep redirecting to self
			http.Redirect(w, r, r.URL.String(), http.StatusFound)
		}))
		defer redirectServer.Close()

		c := newTestHTTPClient("the-token", time.Second*3)
		_, err := c.getUnauthenticated(context.TODO(), redirectServer.URL)
		require.Error(t, err)
		require.Contains(t, err.Error(), "too many redirects")
		// should stop at 10 redirects
		require.LessOrEqual(t, redirectCount, 11)
	})

	t.Run("no auth header on redirected requests", func(t *testing.T) {
		finalServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// verify no auth header is sent (this is a presigned URL scenario)
			assert.Empty(t, r.Header.Get("Authorization"))
			w.Write([]byte("ok"))
		}))
		defer finalServer.Close()

		c := newTestHTTPClient("the-token", time.Second*3)
		resp, err := c.getUnauthenticated(context.TODO(), finalServer.URL)
		require.NoError(t, err)
		require.Equal(t, http.StatusOK, resp.StatusCode)
	})
}
