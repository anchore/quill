package parser

import (
	"github.com/wagoodman/go-partybus"

	"github.com/anchore/quill/quill/event"
)

func Exit(e partybus.Event) error {
	if err := checkEventType(e.Type, event.Exit); err != nil {
		return err
	}

	return nil
}
