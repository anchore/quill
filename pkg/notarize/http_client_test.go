package notarize

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func Test_httpClient_get(t *testing.T) {
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		return
	}))
	defer s.Close()
	c, err := newHTTPClient("the-token", time.Second*3)
	require.NoError(t, err)

	resp, err := c.get(s.URL, nil)
	require.NoError(t, err)
	require.Equal(t, "Bearer the-token", resp.Request.Header.Get("Authorization"))

}

func Test_httpClient_post(t *testing.T) {
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		return
	}))
	defer s.Close()
	c, err := newHTTPClient("the-token", time.Second*3)
	require.NoError(t, err)

	resp, err := c.post(s.URL, nil)
	require.NoError(t, err)
	require.Equal(t, "application/json; charset=UTF-8", resp.Request.Header.Get("Content-Type"))
	require.Equal(t, "Bearer the-token", resp.Request.Header.Get("Authorization"))
}
