package notarize

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"path"
	"strings"
	"sync/atomic"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	awsSession "github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/s3/s3manager"

	"github.com/anchore/quill/internal/log"
)

type api interface {
	submissionRequest(ctx context.Context, request submissionRequest) (*submissionResponse, error)
	uploadBinary(ctx context.Context, response submissionResponse, bin payload) error
	submissionStatusRequest(ctx context.Context, id string) (*submissionStatusResponse, error)
	submissionLogs(ctx context.Context, id string) (string, error)
	submissionList(ctx context.Context) (*submissionListResponse, error)
}

type apiClient struct {
	http *httpClient
	api  string
}

func newAPIClient(token string, httpTimeout time.Duration) *apiClient {
	return &apiClient{
		http: newHTTPClient(token, httpTimeout),
		api:  "https://appstoreconnect.apple.com/notary/v2/submissions",
	}
}

func (s apiClient) submissionRequest(ctx context.Context, request submissionRequest) (*submissionResponse, error) {
	// TODO: tie into context
	log.WithFields("id", request.SubmissionName).Trace("submitting binary to Apple for notarization")

	requestBytes, err := json.Marshal(request)
	if err != nil {
		return nil, err
	}

	response, err := s.http.post(s.api, bytes.NewReader(requestBytes))
	body, err := s.handleResponse(response, err)
	if err != nil {
		return nil, err
	}

	var resp submissionResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

func (s apiClient) uploadBinary(ctx context.Context, response submissionResponse, bin payload) error {
	log.WithFields("digest", bin.Digest).Trace("uploading binary to S3")

	attrs := response.Data.Attributes
	s3Config := &aws.Config{
		Region:      aws.String("us-west-2"),
		Credentials: credentials.NewStaticCredentials(attrs.AwsAccessKeyID, attrs.AwsSecretAccessKey, attrs.AwsSessionToken),
	}
	s3Session, err := awsSession.NewSession(s3Config)
	if err != nil {
		return err
	}

	uploader := s3manager.NewUploader(s3Session)
	input := &s3manager.UploadInput{
		Bucket: aws.String(attrs.Bucket),
		Key:    aws.String(attrs.Object),
		Body: &monitoredReader{
			reader: bin.Reader,
			size:   bin.Size(),
		},
		ContentType: aws.String("application/zip"),
	}

	log.WithFields("bucket", attrs.Bucket, "object", attrs.Object).Trace("binary destination in S3")

	_, err = uploader.UploadWithContext(ctx, input)
	if err != nil {
		return err
	}

	return nil
}

func (s apiClient) submissionStatusRequest(ctx context.Context, id string) (*submissionStatusResponse, error) {
	log.WithFields("id", id).Trace("requesting notarization status")

	response, err := s.http.get(joinURL(s.api, id), nil)
	body, err := s.handleResponse(response, err)
	if err != nil {
		return nil, err
	}

	var resp submissionStatusResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

func (s apiClient) submissionList(ctx context.Context) (*submissionListResponse, error) {
	log.Trace("listing notarization submissions")

	response, err := s.http.get(s.api, nil)
	body, err := s.handleResponse(response, err)
	if err != nil {
		return nil, err
	}

	var resp submissionListResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

func (s apiClient) submissionLogs(ctx context.Context, id string) (string, error) {
	metadataResp, err := s.http.get(joinURL(s.api, id, "logs"), nil)
	body, err := s.handleResponse(metadataResp, err)
	if err != nil {
		return "", fmt.Errorf("unable to fetch log metadata with ID=%s: %w", id, err)
	}

	var resp submissionLogsResponse
	if err := json.NewDecoder(bytes.NewReader(body)).Decode(&resp); err != nil {
		return "", fmt.Errorf("unable to decode log metadata response with ID=%s: %w", id, err)
	}

	logsResp, err := s.http.get(resp.Data.Attributes.DeveloperLogURL, nil)
	contents, err := s.handleResponse(logsResp, err)
	if err != nil {
		return "", fmt.Errorf("unable to fetch log destination with ID=%s: %w", id, err)
	}

	return string(contents), nil
}

func (s apiClient) handleResponse(response *http.Response, err error) ([]byte, error) {
	if err != nil {
		return nil, err
	}

	var body []byte

	if response.Body != nil {
		defer response.Body.Close()

		body, err = io.ReadAll(response.Body)
		if err != nil {
			return nil, err
		}
	}

	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("http status=%q: body=%q", response.Status, string(body))
	}

	return body, nil
}

type monitoredReader struct {
	reader *bytes.Reader
	size   int64
	read   int64 // TODO: expose this
}

func (r *monitoredReader) Read(p []byte) (int, error) {
	return r.reader.Read(p)
}

func (r *monitoredReader) ReadAt(p []byte, off int64) (int, error) {
	n, err := r.reader.ReadAt(p, off)
	atomic.AddInt64(&r.read, int64(n))
	return n, err
}

func (r *monitoredReader) Seek(offset int64, whence int) (int64, error) {
	return r.reader.Seek(offset, whence)
}

func joinURL(base string, paths ...string) string {
	p := path.Join(paths...)
	return fmt.Sprintf("%s/%s", strings.TrimRight(base, "/"), strings.TrimLeft(p, "/"))
}
