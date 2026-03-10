package bus

import (
	"context"
	"errors"

	"github.com/wagoodman/go-partybus"
	"github.com/wagoodman/go-progress"

	"github.com/anchore/bubbly"
	"github.com/anchore/quill/internal/redact"
	"github.com/anchore/quill/quill/event"
)

// ErrPromptCancelled is returned when a prompt is cancelled (e.g., user pressed Ctrl+C).
var ErrPromptCancelled = errors.New("prompt cancelled")

// Canceller is implemented by types that support cancellation.
type Canceller interface {
	Cancel()
}

// Prompter wraps bubbly.Prompter with context-based cancellation support.
// It satisfies both bubbly.PromptWriter and Canceller interfaces.
//
// Design note: storing context in a struct is generally discouraged in Go
// (see https://go.dev/blog/context-and-structs). However, it's acceptable here because:
//   - Prompter represents a single, short-lived prompt operation
//   - The context is scoped to that specific operation's cancellation
//   - The struct is created, used once for Response(), then discarded
//
// The alternative (returning a cancel func separately) was tried but required
// global state to coordinate between the UI and command layers.
type Prompter struct {
	*bubbly.Prompter
	ctx    context.Context
	cancel context.CancelFunc
}

// ensure Prompter satisfies the required interfaces
var (
	_ bubbly.PromptWriter = (*Prompter)(nil)
	_ Canceller           = (*Prompter)(nil)
)

// Response waits for user input and returns it. The call will return ErrPromptCancelled
// if Cancel() is called (e.g., when the user presses Ctrl+C).
func (p *Prompter) Response() (string, error) {
	resp, err := p.Prompter.Response(p.ctx)
	if err != nil {
		// check if our context was cancelled (regardless of how the error is wrapped)
		if p.ctx.Err() != nil {
			return "", ErrPromptCancelled
		}
		return "", err
	}
	return resp, nil
}

// Cancel cancels the prompt, causing any pending Response() call to return ErrPromptCancelled.
func (p *Prompter) Cancel() {
	if p.cancel != nil {
		p.cancel()
	}
}

func PublishTask(titles event.Title, context string, total int) *event.ManualStagedProgress {
	prog := event.ManualStagedProgress{
		Manual: *progress.NewManual(int64(total)),
	}

	publish(partybus.Event{
		Type: event.TaskType,
		Source: event.Task{
			Title:   titles,
			Context: context,
		},
		Value: progress.StagedProgressable(&struct {
			progress.Stager
			progress.Progressable
		}{
			Stager:       &prog.Stage,
			Progressable: &prog.Manual,
		}),
	})

	return &prog
}

func Exit() {
	publish(partybus.Event{
		Type: event.CLIExitType,
	})
}

func Report(report string) {
	if publisher == nil {
		// prevent any further actions taken on the report (such as redaction) since it won't be published anyway
		return
	}
	publish(partybus.Event{
		Type:  event.CLIReportType,
		Value: redact.Apply(report),
	})
}

func Notify(message string) {
	if publisher == nil {
		// prevent any further actions taken on the report (such as redaction) since it won't be published anyway
		return
	}
	publish(partybus.Event{
		Type:  event.CLINotificationType,
		Value: redact.Apply(message),
	})
}

// PromptForInput creates a prompt and publishes it to the event bus.
// The returned Prompter supports cancellation - call prompter.Response() to wait for input,
// which will return context.Canceled if the prompt is cancelled (e.g., via Ctrl+C in the UI).
func PromptForInput(ctx context.Context, message string, sensitive bool, validators ...func(string) error) *Prompter {
	if publisher == nil {
		// prevent any further actions taken on the report (such as redaction) since it won't be published anyway
		return nil
	}

	promptCtx, cancel := context.WithCancel(ctx)
	p := bubbly.NewPrompter(redact.Apply(message), sensitive, validators...)

	prompter := &Prompter{
		Prompter: p,
		ctx:      promptCtx,
		cancel:   cancel,
	}

	publish(partybus.Event{
		Type:  event.CLIInputPromptType,
		Value: prompter,
	})

	return prompter
}
