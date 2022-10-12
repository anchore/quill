package parser

import (
	"github.com/wagoodman/go-partybus"

	"github.com/anchore/quill/quill/event"
	"github.com/anchore/quill/quill/event/monitor"
)

func InputPrompt(e partybus.Event) (monitor.PromptWriter, error) {
	if err := checkEventType(e.Type, event.InputPrompt); err != nil {
		return nil, err
	}

	p, ok := e.Value.(monitor.PromptWriter)
	if !ok {
		return nil, newPayloadErr(e.Type, "Value", e.Value)
	}

	return p, nil
}
