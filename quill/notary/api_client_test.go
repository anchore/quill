package notary

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// newTestAPIClient creates an APIClient configured for test servers (http + 127.0.0.1).
func newTestAPIClient(token string, timeout time.Duration) *APIClient {
	return NewAPIClientWithValidator(token, timeout, testValidator())
}

func Test_apiClient_submissionRequest(t *testing.T) {
	expected := submissionResponse{
		Data: submissionResponseData{
			submissionResponseDescriptor: submissionResponseDescriptor{
				Type: "the-ty",
				ID:   "the-id",
			},
			Attributes: submissionResponseAttributes{
				AwsAccessKeyID:     "key-id",
				AwsSecretAccessKey: "access-key",
				AwsSessionToken:    "token",
				Bucket:             "bucket",
				Object:             "obj",
			},
		},
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		by, err := json.Marshal(expected)
		require.NoError(t, err)
		w.Write(by)
	})

	s := httptest.NewServer(mux)
	defer s.Close()

	c := newTestAPIClient("the-token", time.Second*3)
	c.api = s.URL

	actual, err := c.submissionRequest(context.Background(), submissionRequest{
		Sha256:         "the-digest",
		SubmissionName: "the-name",
	})
	require.NoError(t, err)
	require.NotNil(t, actual)
	require.Equal(t, expected, *actual)
}

func Test_apiClient_submissionStatusRequest(t *testing.T) {

	id := "the-id"
	expected := submissionStatusResponse{
		Data: submissionStatusResponseData{
			submissionResponseDescriptor: submissionResponseDescriptor{
				Type: "the-ty",
				ID:   id,
			},
			Attributes: submissionStatusResponseAttributes{
				Status:      AcceptedStatus,
				Name:        "the-name",
				CreatedDate: time.Now(),
			},
		},
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/"+id, func(w http.ResponseWriter, r *http.Request) {
		by, err := json.Marshal(expected)
		require.NoError(t, err)
		w.Write(by)
	})

	s := httptest.NewServer(mux)
	defer s.Close()

	c := newTestAPIClient("the-token", time.Second*3)
	c.api = s.URL

	actual, err := c.submissionStatusRequest(context.Background(), id)
	require.NoError(t, err)
	require.NotNil(t, actual)

	// don't compare timestamps
	expected.Data.Attributes.CreatedDate = actual.Data.Attributes.CreatedDate

	require.Equal(t, expected, *actual)
}

func Test_apiClient_submissionLogs(t *testing.T) {

	id := "the-id"
	expected := "the-logs"
	expectedLogResponse := submissionLogsResponse{
		Data: submissionLogsResponseData{
			submissionResponseDescriptor: submissionResponseDescriptor{
				Type: "the-ty",
				ID:   id,
			},
		},
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/"+id+"/logs", func(w http.ResponseWriter, r *http.Request) {
		by, err := json.Marshal(expectedLogResponse)
		require.NoError(t, err)
		w.Write(by)
	})

	mux.HandleFunc("/place-where-the-logs-are", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(expected))
	})

	s := httptest.NewServer(mux)
	expectedLogResponse.Data.Attributes.DeveloperLogURL = s.URL + "/place-where-the-logs-are"
	defer s.Close()

	c := newTestAPIClient("the-token", time.Second*3)
	c.api = s.URL

	actual, err := c.submissionLogs(context.Background(), id)
	require.NoError(t, err)
	require.NotNil(t, actual)
	require.Equal(t, expected, actual)
}

func Test_apiClient_submissionLogs_rejectsDeniedURLs(t *testing.T) {
	// tests for URLs that should be outright rejected (tier 2: denylist)
	// note: http and 127.0.0.1 are allowed for test server, so we test other blocked values
	tests := []struct {
		name   string
		logURL string
	}{
		{
			name:   "rejects localhost",
			logURL: "https://localhost/logs",
		},
		{
			name:   "rejects loopback IP",
			logURL: "https://127.0.0.2/logs", // 127.0.0.2 is loopback but not in test allowlist
		},
		{
			name:   "rejects AWS metadata endpoint",
			logURL: "https://169.254.169.254/latest/meta-data",
		},
		{
			name:   "rejects private IP 10.x",
			logURL: "https://10.0.0.1/admin",
		},
		{
			name:   "rejects private IP 192.168.x",
			logURL: "https://192.168.1.1/admin",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			id := "the-id"
			expectedLogResponse := submissionLogsResponse{
				Data: submissionLogsResponseData{
					submissionResponseDescriptor: submissionResponseDescriptor{
						Type: "the-ty",
						ID:   id,
					},
					Attributes: submissionLogsResponseAttributes{
						DeveloperLogURL: tt.logURL,
					},
				},
			}

			mux := http.NewServeMux()
			mux.HandleFunc("/"+id+"/logs", func(w http.ResponseWriter, r *http.Request) {
				by, err := json.Marshal(expectedLogResponse)
				require.NoError(t, err)
				w.Write(by)
			})

			s := httptest.NewServer(mux)
			defer s.Close()

			c := newTestAPIClient("the-token", time.Second*3)
			c.api = s.URL

			_, err := c.submissionLogs(context.Background(), id)
			require.Error(t, err)
			require.Contains(t, err.Error(), "URL validation failed")
		})
	}
}

func Test_apiClient_handleResponse_enforcesMaxSize(t *testing.T) {
	tests := []struct {
		name        string
		size        int
		wantErr     require.ErrorAssertionFunc
		errContains string
	}{
		{
			name: "accepts response under limit",
			size: 1024, // 1 KB
		},
		{
			name: "accepts response at limit",
			size: maxAPIResponseSize,
		},
		{
			name:        "rejects response over limit",
			size:        maxAPIResponseSize + 1,
			wantErr:     require.Error,
			errContains: "exceeds limit",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.wantErr == nil {
				tt.wantErr = require.NoError
			}

			mux := http.NewServeMux()
			mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
				// write a response of the specified size
				data := strings.Repeat("x", tt.size)
				w.Write([]byte(data))
			})

			s := httptest.NewServer(mux)
			defer s.Close()

			resp, err := http.Get(s.URL)
			require.NoError(t, err)

			c := APIClient{}
			_, err = c.handleResponse(resp, nil)
			tt.wantErr(t, err)

			if tt.errContains != "" {
				require.Contains(t, err.Error(), tt.errContains)
			}
		})
	}
}

func Test_apiClient_handleResponseWithLimit_enforcesCustomLimit(t *testing.T) {
	customLimit := int64(100)

	tests := []struct {
		name        string
		size        int
		wantErr     require.ErrorAssertionFunc
		errContains string
	}{
		{
			name: "accepts response under custom limit",
			size: 50,
		},
		{
			name: "accepts response at custom limit",
			size: int(customLimit),
		},
		{
			name:        "rejects response over custom limit",
			size:        int(customLimit) + 1,
			wantErr:     require.Error,
			errContains: "exceeds limit",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.wantErr == nil {
				tt.wantErr = require.NoError
			}

			mux := http.NewServeMux()
			mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
				data := strings.Repeat("x", tt.size)
				w.Write([]byte(data))
			})

			s := httptest.NewServer(mux)
			defer s.Close()

			resp, err := http.Get(s.URL)
			require.NoError(t, err)

			c := APIClient{}
			_, err = c.handleResponseWithLimit(resp, nil, customLimit)
			tt.wantErr(t, err)

			if tt.errContains != "" {
				require.Contains(t, err.Error(), tt.errContains)
			}
		})
	}
}

func Test_apiClient_submissionLogs_usesLargerLimit(t *testing.T) {
	// create a log response larger than maxAPIResponseSize but smaller than maxLogResponseSize
	logSize := maxAPIResponseSize + 1024 // just over the API limit
	require.True(t, logSize < maxLogResponseSize, "test assumes logSize < maxLogResponseSize")

	id := "the-id"
	expectedLogResponse := submissionLogsResponse{
		Data: submissionLogsResponseData{
			submissionResponseDescriptor: submissionResponseDescriptor{
				Type: "the-ty",
				ID:   id,
			},
		},
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/"+id+"/logs", func(w http.ResponseWriter, r *http.Request) {
		by, err := json.Marshal(expectedLogResponse)
		require.NoError(t, err)
		w.Write(by)
	})

	mux.HandleFunc("/place-where-the-logs-are", func(w http.ResponseWriter, r *http.Request) {
		// write a large log response
		data := strings.Repeat("x", logSize)
		w.Write([]byte(data))
	})

	s := httptest.NewServer(mux)
	expectedLogResponse.Data.Attributes.DeveloperLogURL = s.URL + "/place-where-the-logs-are"
	defer s.Close()

	c := newTestAPIClient("the-token", time.Second*30)
	c.api = s.URL

	// this should succeed because logs use maxLogResponseSize, not maxAPIResponseSize
	actual, err := c.submissionLogs(context.Background(), id)
	require.NoError(t, err)
	require.Len(t, actual, logSize)
}
