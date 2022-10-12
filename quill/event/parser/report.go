package parser

import (
	"github.com/wagoodman/go-partybus"

	"github.com/anchore/quill/quill/event"
)

func Report(e partybus.Event) (string, string, error) {
	if err := checkEventType(e.Type, event.Report); err != nil {
		return "", "", err
	}

	context, ok := e.Source.(string)
	if !ok {
		// this is optional
		context = ""
	}

	report, ok := e.Value.(string)
	if !ok {
		return "", "", newPayloadErr(e.Type, "Value", e.Value)
	}

	return context, report, nil
}
