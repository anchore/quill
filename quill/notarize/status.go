package notarize

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/anchore/quill/internal/log"
)

type statusConfig struct {
	timeout time.Duration
	poll    time.Duration
	wait    bool
}

func Status(id string, cfg Config) error {
	log.Infof("checking submission status for %q", id)

	token, err := newSignedToken(cfg.tokenConfig)
	if err != nil {
		return err
	}

	a := newAPIClient(token, cfg.httpTimeout)

	sub := newSubmissionFromExisting(a, id)

	status, err := pollStatus(context.Background(), sub, cfg.statusConfig)
	fmt.Println(status)

	return err
}

func pollStatus(ctx context.Context, sub *submission, cfg statusConfig) (SubmissionStatus, error) {
	var err error

	ctx, cancel := context.WithTimeout(ctx, cfg.timeout)
	defer cancel()

	var status SubmissionStatus = PendingStatus

	for !status.isCompleted() {
		select {
		case <-ctx.Done():
			return "", errors.New("timeout waiting for notarize submission response")

		default:
			status, err = sub.status(ctx)
			if err != nil {
				return "", err
			}
		}

		time.Sleep(cfg.poll)
	}

	if !status.isSuccessful() {
		logs, err := sub.logs(ctx)
		if err != nil {
			return "", err
		}
		return "", fmt.Errorf("submission result is %+v: %+v", status, logs)
	}

	return status, nil
}
