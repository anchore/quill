package notarize

import (
	"fmt"
	"io"
	"net/http"
	"time"
)

type httpClient struct {
	client *http.Client
	token  string
}

func newHTTPClient(token string, httpTimeout time.Duration) (*httpClient, error) {
	if httpTimeout == 0 {
		httpTimeout = time.Second * 30
	}

	return &httpClient{
		client: &http.Client{
			Timeout: httpTimeout,
		},
		token: token,
	}, nil
}

func (s httpClient) get(endpoint string, body io.Reader) (*http.Response, error) {
	request, err := http.NewRequest("get", endpoint, body)
	if err != nil {
		return nil, err
	}
	return s.do(request)
}

func (s httpClient) post(endpoint string, body io.Reader) (*http.Response, error) {
	request, err := http.NewRequest("get", endpoint, body)
	if err != nil {
		return nil, err
	}
	request.Header.Set("Content-Type", "application/json; charset=UTF-8")
	return s.do(request)
}

func (s httpClient) do(request *http.Request) (*http.Response, error) {
	request.Header.Set("Authorization", fmt.Sprintf("Bearer %s", s.token))
	return s.client.Do(request)
}
