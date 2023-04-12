package parser

import (
	"github.com/wagoodman/go-partybus"

	"github.com/anchore/quill/quill/event"
)

func Exit(e partybus.Event) error {
	return checkEventType(e.Type, event.Exit)
}
