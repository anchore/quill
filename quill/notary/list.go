package notary

// import (
//	"context"
//	"fmt"
//
//	"github.com/jedib0t/go-pretty/table"
//
//	"github.com/anchore/quill/internal/log"
//)
//
// func List(cfg SigningConfig) error {
//	log.Info("fetching previous submissions")
//
//	token, err := NewSignedToken(cfg.TokenConfig)
//	if err != nil {
//		return err
//	}
//
//	a := NewAPIClient(token, cfg.HttpTimeout)
//
//	sub := NewSubmissionFromExisting(a, "")
//
//	submissions, err := sub.List(context.Background())
//	if err != nil {
//		return err
//	}
//
//	t := table.NewWriter()
//	t.SetStyle(table.StyleLight)
//
//	t.AppendHeader(table.Row{"ID", "Name", "Status", "Created"})
//
//	for _, item := range submissions {
//		t.AppendRow(table.Row{item.ID, item.Name, item.Status, item.CreatedDate})
//	}
//
//	fmt.Println(t.Render())
//
//	return nil
//}
