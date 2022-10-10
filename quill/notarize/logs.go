package notarize

import (
	"context"
	"fmt"

	"github.com/anchore/quill/internal/log"
)

func Logs(id string, cfg Config) error {
	log.Infof("fetching logs for submission %q", id)

	token, err := newSignedToken(cfg.tokenConfig)
	if err != nil {
		return err
	}

	a := newAPIClient(token, cfg.httpTimeout)

	sub := newSubmissionFromExisting(a, id)

	logs, err := sub.logs(context.Background())
	if err != nil {
		return err
	}

	if logs == "" {
		logs = "no logs available"
	}

	fmt.Println(logs)

	return nil
}
