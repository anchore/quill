package ui

import (
	"github.com/wagoodman/go-partybus"

	"github.com/anchore/clio"
	"github.com/anchore/quill/quill/event"
)

var _ clio.UI = (*NoUI)(nil)

type NoUI struct {
	finalizeEvents []partybus.Event
	subscription   partybus.Unsubscribable
}

func None() *NoUI {
	return &NoUI{}
}

func (n *NoUI) Setup(subscription partybus.Unsubscribable) error {
	n.subscription = subscription
	return nil
}

func (n *NoUI) Handle(e partybus.Event) error {
	switch e.Type {
	case event.CLIReportType, event.CLINotificationType:
		// keep these for when the UI is terminated to show to the screen (or perform other events)
		n.finalizeEvents = append(n.finalizeEvents, e)
	case event.CLIExitType:
		return n.subscription.Unsubscribe()
	}
	return nil
}

func (n NoUI) Teardown(_ bool) error {
	postUIEvents(false, n.finalizeEvents...)
	return nil
}
