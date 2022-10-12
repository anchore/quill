package loggerui

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/wagoodman/go-partybus"
	"github.com/wagoodman/go-progress"

	"github.com/anchore/go-logger"
	"github.com/anchore/quill/internal/log"
	"github.com/anchore/quill/internal/ui/handle"
	"github.com/anchore/quill/quill/event"
)

type UI struct {
	unsubscribe func() error
	logger      logger.Logger
	debug       bool
	quiet       bool
	background  *sync.WaitGroup
	finalizers  []partybus.Event
}

// New writes all events to the common application logger and writes the final report to the given writer.

func New(debug, quiet bool) *UI {
	return &UI{
		debug:      debug,
		quiet:      quiet,
		logger:     log.Nested("from", "UI"),
		background: &sync.WaitGroup{},
	}
}

func (u *UI) Setup(unsubscribe func() error) error {
	u.unsubscribe = unsubscribe
	return nil
}

func (u *UI) Handle(e partybus.Event) error {
	if u.debug {
		u.handleEvent(e)
	}

	switch e.Type {
	case event.Exit:
		u.finalizers = append(u.finalizers, e)
		return u.unsubscribe()
	case event.Report, event.Notification:
		u.finalizers = append(u.finalizers, e)
	case event.InputPrompt:
		if err := u.handleInputPrompt(e); err != nil {
			return err
		}
	}

	return nil
}

func (u UI) Teardown(force bool) error {
	if !force {
		u.background.Wait()
	}

	handle.PostUIEvents(u.quiet, u.finalizers...)

	return nil
}

func (u *UI) logEventPoll(localLogger logger.Logger, p progress.Progress, stage string) {
	fields := make(logger.Fields)
	if p.Size() > 0 {
		fields["size"] = p.Size()
		fields["ratio"] = fmt.Sprintf("%0.2f", p.Ratio())
	}
	if stage != "" {
		fields["stage"] = stage
	}
	if p.Current() > 0 {
		fields["n"] = p.Current()
	}
	err := p.Error()
	if err != nil && !errors.Is(err, progress.ErrCompleted) {
		fields["error"] = err
	}

	if p.Complete() {
		fields["finished"] = p.Complete()
	}

	localLogger.
		WithFields(fields).
		Debugf("polling event progress")
}

func (u *UI) handleEvent(e partybus.Event) {
	eventFields := make(logger.Fields)
	eventFields["event"] = e.Type
	if e.Source != nil {
		eventFields["source"] = e.Source
	}

	localLogger := u.logger.Nested(eventFields)

	localLogger.Debug("new event")

	prog, ok := e.Value.(progress.Progressable)
	if !ok {
		return
	}

	u.background.Add(1)
	go func() {
		defer u.background.Done()

		var stager progress.Stager = progress.Stage{}
		if s, ok := e.Value.(progress.Stager); ok {
			stager = s
		}

		var last progress.Progress
		var lastStage string
		var lastShow = time.Now()
		for current := range progress.Stream(context.Background(), prog, time.Second*1) {
			stage := stager.Stage()

			// try to only log progress updates when there is either new information, or it's been a while since the last log
			hasUpdatedInfo := last != current || lastStage != stage
			isStale := lastShow.Add(5 * time.Second).Before(time.Now())
			if hasUpdatedInfo || isStale {
				u.logEventPoll(localLogger, current, stage)

				lastShow = time.Now()
			}
			lastStage = stage
			last = current
		}

		if !last.Complete() {
			localLogger.Debugf("event progress finished in an incomplete state")
		}
	}()
}
