package notary

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
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
	"github.com/anchore/quill/internal/utils"
)

const (
	maxAPIResponseSize = 5 * 1024 * 1024  // 5 MB for API JSON responses
	maxLogResponseSize = 50 * 1024 * 1024 // 50 MB for log files
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

	response, err := s.http.post(ctx, s.api, bytes.NewReader(requestBytes)) //nolint:bodyclose // body is closed in handleResponse
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
	response, err := s.http.get(ctx, joinURL(s.api, id), nil) //nolint:bodyclose // body is closed in handleResponse
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
	response, err := s.http.get(ctx, s.api, nil) //nolint:bodyclose // body is closed in handleResponse
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
	metadataResp, err := s.http.get(ctx, joinURL(s.api, id, "logs"), nil) //nolint:bodyclose // body is closed in handleResponse
	body, err := s.handleResponse(metadataResp, err)
	if err != nil {
		return "", fmt.Errorf("unable to fetch log metadata with ID=%s: %w", id, err)
	}

	var resp submissionLogsResponse
	if err := json.NewDecoder(bytes.NewReader(body)).Decode(&resp); err != nil {
		return "", fmt.Errorf("unable to decode log metadata response with ID=%s: %w", id, err)
	}

	redactPresignedURLParams(resp.Data.Attributes.DeveloperLogURL)

	// fetch logs without auth (presigned URL), with redirect validation for SSRF protection.
	// use a larger size limit since log files can be bigger than typical API responses.
	logsResp, err := s.http.getUnauthenticated(ctx, resp.Data.Attributes.DeveloperLogURL)
	contents, err := s.handleResponseWithLimit(logsResp, err, maxLogResponseSize)
	if err != nil {
		return "", fmt.Errorf("unable to fetch log destination with ID=%s: %w", id, err)
	}

	return string(contents), nil
}

func (s APIClient) handleResponse(response *http.Response, err error) ([]byte, error) {
	return s.handleResponseWithLimit(response, err, maxAPIResponseSize)
}

func (s APIClient) handleResponseWithLimit(response *http.Response, err error, maxBytes int64) ([]byte, error) {
	// ensure body is always closed, even if there's an error
	if response != nil && response.Body != nil {
		defer response.Body.Close()
	}

	if err != nil {
		return nil, err
	}

	if response == nil {
		return nil, fmt.Errorf("nil response")
	}

	var body []byte

	if response.Body != nil {
		// limit response size to prevent memory exhaustion from malicious responses
		body, err = utils.ReadAllLimited(response.Body, maxBytes)
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
