package parser

import (
	"github.com/wagoodman/go-partybus"

	"github.com/anchore/quill/quill/event"
)

func Notification(e partybus.Event) (string, string, error) {
	if err := checkEventType(e.Type, event.Notification); err != nil {
		return "", "", err
	}

	context, ok := e.Source.(string)
	if !ok {
		// this is optional
		context = ""
	}

	notification, ok := e.Value.(string)
	if !ok {
		return "", "", newPayloadErr(e.Type, "Value", e.Value)
	}

	return context, notification, nil
}
