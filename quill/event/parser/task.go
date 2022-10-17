package parser

import (
	"github.com/wagoodman/go-partybus"
	"github.com/wagoodman/go-progress"

	"github.com/anchore/quill/quill/event"
	"github.com/anchore/quill/quill/event/monitor"
)

func Task(e partybus.Event) (*monitor.Task, progress.StagedProgressable, error) {
	if err := checkEventType(e.Type, event.Task); err != nil {
		return nil, nil, err
	}

	cmd, ok := e.Source.(monitor.Task)
	if !ok {
		return nil, nil, newPayloadErr(e.Type, "Source", e.Source)
	}

	p, ok := e.Value.(progress.StagedProgressable)
	if !ok {
		return nil, nil, newPayloadErr(e.Type, "Value", e.Value)
	}

	return &cmd, p, nil
}
