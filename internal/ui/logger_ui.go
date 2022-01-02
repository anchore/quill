package ui

import (
	"io"

	"github.com/wagoodman/go-partybus"
	"github.com/wagoodman/quill/pkg/event"
)

type loggerUI struct {
	unsubscribe  func() error
	reportOutput io.Writer
}

// NewLoggerUI writes all events to the common application logger and writes the final report to the given writer.
func NewLoggerUI(reportWriter io.Writer) UI {
	return &loggerUI{
		reportOutput: reportWriter,
	}
}

func (l *loggerUI) Setup(unsubscribe func() error) error {
	l.unsubscribe = unsubscribe
	return nil
}

func (l loggerUI) Handle(e partybus.Event) error {
	// ignore all events except for the final event
	if e.Type == event.Exit {
		return l.unsubscribe()
	}

	return nil
}

func (l loggerUI) Teardown(_ bool) error {
	return nil
}
