package notary

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"
	"strings"
	"sync/atomic"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/feature/s3/manager"
	"github.com/aws/aws-sdk-go-v2/service/s3"

	"github.com/anchore/quill/internal/log"
	"github.com/anchore/quill/internal/redact"
	"github.com/anchore/quill/internal/urlvalidate"
)

type api interface {
	submissionRequest(ctx context.Context, request submissionRequest) (*submissionResponse, error)
	uploadBinary(ctx context.Context, response submissionResponse, bin Payload) error
	submissionStatusRequest(ctx context.Context, id string) (*submissionStatusResponse, error)
	submissionLogs(ctx context.Context, id string) (string, error)
	submissionList(ctx context.Context) (*submissionListResponse, error)
}

type APIClient struct {
	http *httpClient
	api  string
}

// NewAPIClient creates a new APIClient with the default URL validator configuration.
func NewAPIClient(token string, httpTimeout time.Duration) *APIClient {
	return NewAPIClientWithValidator(token, httpTimeout, nil)
}

// NewAPIClientWithValidator creates a new APIClient with a custom URL validator.
// If validator is nil, a default validator with production settings will be used.
func NewAPIClientWithValidator(token string, httpTimeout time.Duration, validator *urlvalidate.Validator) *APIClient {
	if validator == nil {
		validator = urlvalidate.New(urlvalidate.DefaultConfig())
	}
	return &APIClient{
		http: newHTTPClient(token, httpTimeout, validator),
		api:  "https://appstoreconnect.apple.com/notary/v2/submissions",
	}
}

func (s APIClient) submissionRequest(ctx context.Context, request submissionRequest) (*submissionResponse, error) {
	// TODO: tie into context
	log.WithFields("name", request.SubmissionName).Trace("submitting binary to Apple for notarization")

	requestBytes, err := json.Marshal(request)
	if err != nil {
		return nil, err
	}

	response, err := s.http.post(ctx, s.api, bytes.NewReader(requestBytes))
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

func (s APIClient) uploadBinary(ctx context.Context, response submissionResponse, bin Payload) error {
	attrs := response.Data.Attributes
	log.WithFields("bucket", attrs.Bucket, "object", attrs.Object).Trace("uploading binary to S3")

	// there is currently no path that would log these values, but let the redactor know about them just in case
	redact.Add(attrs.AwsAccessKeyID, attrs.AwsSecretAccessKey, attrs.AwsSessionToken)

	// create AWS config with static credentials
	cfg, err := config.LoadDefaultConfig(ctx,
		config.WithRegion("us-west-2"),
		config.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(
			attrs.AwsAccessKeyID,
			attrs.AwsSecretAccessKey,
			attrs.AwsSessionToken,
		)),
	)
	if err != nil {
		return err
	}

	// create S3 client and uploader
	client := s3.NewFromConfig(cfg)
	uploader := manager.NewUploader(client)

	input := &s3.PutObjectInput{
		Bucket: aws.String(attrs.Bucket),
		Key:    aws.String(attrs.Object),
		Body: &monitoredReader{
			reader: bin.Reader,
			size:   bin.Size(),
		},
		ContentType: aws.String("application/zip"),
	}

	_, err = uploader.Upload(ctx, input)
	if err != nil {
		return err
	}

	return nil
}

func (s APIClient) submissionStatusRequest(ctx context.Context, id string) (*submissionStatusResponse, error) {
	response, err := s.http.get(ctx, joinURL(s.api, id), nil)
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

func (s APIClient) submissionList(ctx context.Context) (*submissionListResponse, error) {
	response, err := s.http.get(ctx, s.api, nil)
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

func (s APIClient) submissionLogs(ctx context.Context, id string) (string, error) {
	metadataResp, err := s.http.get(ctx, joinURL(s.api, id, "logs"), nil)
	body, err := s.handleResponse(metadataResp, err)
	if err != nil {
		return "", fmt.Errorf("unable to fetch log metadata with ID=%s: %w", id, err)
	}

	var resp submissionLogsResponse
	if err := json.NewDecoder(bytes.NewReader(body)).Decode(&resp); err != nil {
		return "", fmt.Errorf("unable to decode log metadata response with ID=%s: %w", id, err)
	}

	redactPresignedURLParams(resp.Data.Attributes.DeveloperLogURL)

	// fetch logs without auth header (it's a presigned URL with its own auth)
	logsResp, err := s.http.getUnauthenticated(ctx, resp.Data.Attributes.DeveloperLogURL)
	contents, err := s.handleResponse(logsResp, err)
	if err != nil {
		return "", fmt.Errorf("unable to fetch log destination with ID=%s: %w", id, err)
	}

	return string(contents), nil
}

func (s APIClient) handleResponse(response *http.Response, err error) ([]byte, error) {
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

func redactPresignedURLParams(rawURL string) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return
	}

	// check both v2 and v4 signature parameter names (case-sensitive in query strings)
	params := []string{
		"AWSAccessKeyId",       // v2 signature
		"Signature",            // v2 signature
		"x-amz-security-token", // v2 signature
		"X-Amz-Security-Token", // v4 signature
		"X-Amz-Signature",      // v4 signature
		"X-Amz-Credential",     // v4 signature
	}

	for _, p := range params {
		if v := u.Query().Get(p); v != "" {
			// add both decoded and URL-encoded versions since URLs may be logged either way
			redact.Add(v)
			if encoded := url.QueryEscape(v); encoded != v {
				redact.Add(encoded)
			}
		}
	}
}

func joinURL(base string, paths ...string) string {
	p := path.Join(paths...)
	return fmt.Sprintf("%s/%s", strings.TrimRight(base, "/"), strings.TrimLeft(p, "/"))
}
