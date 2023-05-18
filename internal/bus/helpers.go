package bus

import (
	"github.com/anchore/bubbly"
	"github.com/wagoodman/go-partybus"
	"github.com/wagoodman/go-progress"

	"github.com/anchore/quill/quill/event"
)

func PublishTask(titles event.Title, context string, total int) *event.ManualStagedProgress {
	prog := event.ManualStagedProgress{
		Manual: progress.Manual{
			Total: int64(total),
		},
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
	publish(partybus.Event{
		Type:  event.CLIReportType,
		Value: report,
	})
}

func Notify(message string) {
	publish(partybus.Event{
		Type:  event.CLINotificationType,
		Value: message,
	})
}

func PromptForInput(message string, sensitive bool, validators ...func(string) error) *bubbly.Prompter {
	p := bubbly.NewPrompter(message, sensitive, validators...)
	publish(partybus.Event{
		Type:  event.CLIInputPromptType,
		Value: bubbly.PromptWriter(p),
	})

	return p
}
