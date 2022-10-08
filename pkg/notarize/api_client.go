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
)

type api interface {
	submissionRequest(ctx context.Context, request submissionRequest) (*submissionResponse, error)
	uploadBinary(ctx context.Context, response submissionResponse, bin payload) error
	submissionStatusRequest(ctx context.Context, id string) (*submissionStatusResponse, error)
	submissionLogs(ctx context.Context, id string) (string, error)
}

type apiClient struct {
	http *httpClient
	api  string
}

func newAPIClient(token string, httpTimeout time.Duration) (*apiClient, error) {
	c, err := newHTTPClient(token, httpTimeout)
	if err != nil {
		return nil, err
	}
	return &apiClient{
		http: c,
		api:  "https://appstoreconnect.apple.com/notary/v2/submissions",
	}, nil
}

func (s apiClient) submissionRequest(ctx context.Context, request submissionRequest) (*submissionResponse, error) {
	// TODO: tie into context

	requestBytes, err := json.Marshal(request)
	if err != nil {
		return nil, err
	}

	response, err := s.http.post(s.api, bytes.NewReader(requestBytes))
	if err != nil {
		return nil, err
	}

	defer response.Body.Close()

	body, err := io.ReadAll(response.Body)
	if err != nil {
		return nil, err
	}

	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unable to start submission: %+v %+v", response.Status, string(body))
	}

	var resp submissionResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

func (s apiClient) uploadBinary(ctx context.Context, response submissionResponse, bin payload) error {
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

	_, err = uploader.UploadWithContext(ctx, input)
	if err != nil {
		return err
	}

	return nil
}

func (s apiClient) submissionStatusRequest(ctx context.Context, id string) (*submissionStatusResponse, error) {
	response, err := s.http.get(joinURL(s.api, id), nil)
	if err != nil {
		return nil, err
	}

	defer response.Body.Close()

	body, err := io.ReadAll(response.Body)
	if err != nil {
		return nil, err
	}

	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unable to check status for ID=%s: %s %+v", id, response.Status, body)
	}

	var resp submissionStatusResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

func (s apiClient) submissionLogs(ctx context.Context, id string) (string, error) {
	metadataResp, err := s.http.get(joinURL(s.api, id, "logs"), nil)
	if err != nil {
		return "", fmt.Errorf("unable to fetch log metadata with ID=%s: %w", id, err)
	}

	defer metadataResp.Body.Close()

	if metadataResp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("fetch log metadata failed with ID=%s: %s", id, metadataResp.Status)
	}

	var resp submissionLogsResponse
	if err := json.NewDecoder(metadataResp.Body).Decode(&resp); err != nil {
		return "", fmt.Errorf("unable to decode log metadata response with ID=%s: %w", id, err)
	}

	logsResp, err := s.http.get(resp.Data.Attributes.DeveloperLogURL, nil)
	if err != nil {
		return "", fmt.Errorf("unable to fetch log contents with ID=%s: %w", id, err)
	}

	defer logsResp.Body.Close()

	if logsResp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("fetch log contents failed with ID=%s: %s", id, logsResp.Status)
	}

	contents, err := io.ReadAll(logsResp.Body)
	if err != nil {
		return "", fmt.Errorf("unable to read log contents: %w", err)
	}

	return string(contents), nil
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
