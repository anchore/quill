package notarize

import (
	"context"
	"fmt"
	"path/filepath"
	"time"
)

type SubmissionStatus string

const (
	AcceptedStatus = "success"
	PendingStatus  = "pending"
	InvalidStatus  = "invalid"
	RejectedStatus = "rejected"
	TimeoutStatus  = "timeout"
)

func (s SubmissionStatus) isCompleted() bool {
	switch s {
	case AcceptedStatus, RejectedStatus, InvalidStatus, TimeoutStatus:
		return true
	default:
		return false
	}
}

func (s SubmissionStatus) isSuccessful() bool {
	return s == AcceptedStatus
}

type submission struct {
	api    api
	binary payload
	name   string
	id     string
}

func newSubmission(a api, bin *payload) *submission {
	return &submission{
		name:   filepath.Base(bin.Path + "-" + bin.Digest + "-" + time.Now().Format(time.RFC3339)),
		binary: *bin,
		api:    a,
	}
}

func (s *submission) start(ctx context.Context) error {
	response, err := s.api.submissionRequest(
		ctx,
		submissionRequest{
			Sha256:         s.binary.Digest,
			SubmissionName: s.name,
		},
	)

	if err != nil {
		return err
	}

	s.id = response.Data.ID

	return s.api.uploadBinary(ctx, *response, s.binary)
}

func (s submission) status(ctx context.Context) (SubmissionStatus, error) {
	response, err := s.api.submissionStatusRequest(ctx, s.id)
	if err != nil {
		return "", err
	}

	switch response.Data.Attributes.Status {
	case "In Progress":
		return PendingStatus, nil
	case "Accepted":
		return AcceptedStatus, nil
	case "Invalid":
		return InvalidStatus, nil
	case "Rejected":
		return RejectedStatus, nil
	default:
		return "", fmt.Errorf("unexpected status: %s", response.Data.Attributes.Status)
	}
}

func (s submission) logs(ctx context.Context) (string, error) {
	return s.api.submissionLogs(ctx, s.id)
}
