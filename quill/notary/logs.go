package notary

// import (
//	"context"
//	"fmt"
//
//	"github.com/anchore/quill/internal/log"
//)
//
// func Logs(id string, cfg SigningConfig) error {
//	log.Infof("fetching logs for Submission %q", id)
//
//	token, err := NewSignedToken(cfg.TokenConfig)
//	if err != nil {
//		return err
//	}
//
//	a := NewAPIClient(token, cfg.HttpTimeout)
//
//	sub := NewSubmissionFromExisting(a, id)
//
//	logs, err := sub.Logs(context.Background())
//	if err != nil {
//		return err
//	}
//
//	if logs == "" {
//		logs = "no logs available"
//	}
//
//	fmt.Println(logs)
//
//	return nil
//}
