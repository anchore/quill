package notarize

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/anchore/quill/internal/log"
)

func Status(id string, cfg Config) error {
	log.Infof("checking submission status for %q", id)

	token, err := newSignedToken(cfg.tokenConfig)
	if err != nil {
		return err
	}

	a := newAPIClient(token, cfg.httpTimeout)

	sub := newSubmissionFromExisting(a, id)

	ctx, cancel := context.WithTimeout(context.Background(), cfg.Timeout)
	defer cancel()

	var status SubmissionStatus = PendingStatus

	for !status.isCompleted() {
		select {
		case <-ctx.Done():
			return errors.New("timeout waiting for notarize submission response")

		default:
			time.Sleep(cfg.Poll)

			status, err = sub.status(ctx)
			if err != nil {
				return err
			}
		}
	}

	if !status.isSuccessful() {
		logs, err := sub.logs(ctx)
		if err != nil {
			return err
		}
		return fmt.Errorf("submission result is %+v: %+v", status, logs)
	}

	return nil
}
