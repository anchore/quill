package notary

import (
	"context"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

type mockAPI struct {
	requestResponse *submissionResponse
	statusResponse  *submissionStatusResponse
	logsResponse    string
	listResponse    *submissionListResponse
	err             error
	called          []string
}

func newMockAPI() *mockAPI {
	return &mockAPI{}
}

func (m *mockAPI) mockStatus(status string) *mockAPI {
	m.statusResponse = &submissionStatusResponse{
		Data: submissionStatusResponseData{
			Attributes: submissionStatusResponseAttributes{
				Status: status,
			},
		},
	}
	return m
}

func (m *mockAPI) submissionRequest(ctx context.Context, request submissionRequest) (*submissionResponse, error) {
	m.called = append(m.called, "submit")
	return m.requestResponse, m.err
}

func (m *mockAPI) uploadBinary(ctx context.Context, response submissionResponse, bin Payload) error {
	m.called = append(m.called, "upload")
	return m.err
}

func (m *mockAPI) submissionStatusRequest(ctx context.Context, id string) (*submissionStatusResponse, error) {
	m.called = append(m.called, "status")
	return m.statusResponse, m.err
}

func (m *mockAPI) submissionLogs(ctx context.Context, id string) (string, error) {
	m.called = append(m.called, "logs")
	return m.logsResponse, m.err
}

func (m *mockAPI) submissionList(ctx context.Context) (*submissionListResponse, error) {
	return m.listResponse, m.err
}

func Test_submission_status(t *testing.T) {
	type fields struct {
		api api
	}
	type args struct {
		ctx context.Context
	}
	tests := []struct {
		name    string
		fields  fields
		want    SubmissionStatus
		wantErr bool
	}{
		{
			name: "status is in progress",
			fields: fields{
				api: newMockAPI().mockStatus("In Progress"),
			},
			want: PendingStatus,
		},
		{
			name: "status accepted",
			fields: fields{
				api: newMockAPI().mockStatus("Accepted"),
			},
			want: AcceptedStatus,
		},
		{
			name: "status rejected",
			fields: fields{
				api: newMockAPI().mockStatus("Rejected"),
			},
			want: RejectedStatus,
		},
		{
			name: "status invalid",
			fields: fields{
				api: newMockAPI().mockStatus("Invalid"),
			},
			want: InvalidStatus,
		},
		{
			name: "bogus status",
			fields: fields{
				api: newMockAPI().mockStatus("bogosity"),
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := Submission{
				api:  tt.fields.api,
				name: "the-id",
			}
			got, err := s.Status(context.Background())
			if (err != nil) != tt.wantErr {
				t.Errorf("status() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("status() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_submission_start(t *testing.T) {
	type fields struct {
		api *mockAPI
	}
	tests := []struct {
		name    string
		fields  fields
		wantErr bool
	}{
		{
			name: "success",
			fields: fields{
				api: &mockAPI{
					requestResponse: &submissionResponse{
						Data: submissionResponseData{
							submissionResponseDescriptor: submissionResponseDescriptor{
								Type: "ty",
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
					},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := NewSubmission(tt.fields.api, &Payload{
				Path:   "some/place/to/the/path",
				Digest: "sha256:the-best-sha-you've-ever-seen",
			})
			if err := s.Start(context.Background()); (err != nil) != tt.wantErr {
				t.Errorf("start() error = %v, wantErr %v", err, tt.wantErr)
			}
			assert.Equal(t, []string{"submit", "upload"}, tt.fields.api.called)
			assert.True(t, strings.HasPrefix(s.name, "path-sha256:the-best-sha-you've-ever-seen-"), "Submission name should be prefixed with the payload digest, got %q", s.name)
		})
	}
}
