package notarize

import (
	"context"
	"fmt"

	"github.com/jedib0t/go-pretty/table"

	"github.com/anchore/quill/internal/log"
)

func List(cfg Config) error {
	log.Info("fetching previous submissions")

	token, err := newSignedToken(cfg.tokenConfig)
	if err != nil {
		return err
	}

	a := newAPIClient(token, cfg.httpTimeout)

	sub := newSubmissionFromExisting(a, "")

	submissions, err := sub.list(context.Background())
	if err != nil {
		return err
	}

	t := table.NewWriter()
	t.SetStyle(table.StyleLight)

	t.AppendHeader(table.Row{"Name", "Status", "Created"})

	for _, item := range submissions {
		t.AppendRow(table.Row{item.Name, item.Status, item.CreatedDate})
	}

	fmt.Println(t.Render())

	return nil
}
