package notary

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

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

	c := NewAPIClient("the-token", time.Second*3)
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

	c := NewAPIClient("the-token", time.Second*3)
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

	c := NewAPIClient("the-token", time.Second*3)
	c.api = s.URL

	actual, err := c.submissionLogs(context.Background(), id)
	require.NoError(t, err)
	require.NotNil(t, actual)
	require.Equal(t, expected, actual)
}
