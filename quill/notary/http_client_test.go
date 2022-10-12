package notary

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_httpClient_get(t *testing.T) {
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "get", r.Method)
		return
	}))
	defer s.Close()
	c := newHTTPClient("the-token", time.Second*3)

	resp, err := c.get(context.TODO(), s.URL, nil)
	require.NoError(t, err)
	require.Equal(t, "Bearer the-token", resp.Request.Header.Get("Authorization"))

}

func Test_httpClient_post(t *testing.T) {
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "post", r.Method)
		return
	}))
	defer s.Close()
	c := newHTTPClient("the-token", time.Second*3)

	resp, err := c.post(context.TODO(), s.URL, nil)
	require.NoError(t, err)
	require.Equal(t, "application/json; charset=UTF-8", resp.Request.Header.Get("Content-Type"))
	require.Equal(t, "Bearer the-token", resp.Request.Header.Get("Authorization"))
}
