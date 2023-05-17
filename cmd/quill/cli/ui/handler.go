package ui

import (
	"sync"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/wagoodman/go-partybus"
	"github.com/wagoodman/go-progress"

	"github.com/anchore/quill/cmd/quill/internal/ui/bubbles/prompt"
	"github.com/anchore/quill/cmd/quill/internal/ui/bubbles/taskprogress"
	"github.com/anchore/quill/internal/log"
	"github.com/anchore/quill/quill/event"
)

var _ partybus.Responder = (*Handler)(nil)

type handlerFn func(e partybus.Event) tea.Model

type Handler struct {
	state    *State
	dispatch map[partybus.EventType]handlerFn
	types    []partybus.EventType
}

type State struct {
	WindowSize tea.WindowSizeMsg
	Running    *sync.WaitGroup
}

func New() *Handler {
	h := &Handler{
		state: &State{
			Running: &sync.WaitGroup{},
		},
	}

	h.dispatch = map[partybus.EventType]handlerFn{
		event.CLIInputPromptType: h.handleInputPrompt,
		event.TaskType:           h.handleTask,
	}

	types := make([]partybus.EventType, 0, len(h.dispatch))
	for k := range h.dispatch {
		types = append(types, k)
	}

	h.types = types

	return h
}

func (m *Handler) State() *State {
	return m.state
}

func (m *Handler) RespondsTo() []partybus.EventType {
	return m.types
}

func (m *Handler) Handle(e partybus.Event) tea.Model {
	if fn, ok := m.dispatch[e.Type]; ok {
		return fn(e)
	}
	return nil
}

func (m *Handler) handleInputPrompt(e partybus.Event) tea.Model {
	writer, err := event.ParseCLIInputPromptType(e)
	if err != nil {
		log.Warnf("unable to parse event: %+v", err)
		return nil
	}

	return prompt.New(writer)
}

func (m *Handler) handleTask(e partybus.Event) tea.Model {
	cmd, prog, err := event.ParseTaskType(e)
	if err != nil {
		log.Warnf("unable to parse event: %+v", err)
		return nil
	}

	return m.handleStagedProgressable(prog, taskprogress.Title{
		Default: cmd.Title.Default,
		Running: cmd.Title.WhileRunning,
		Success: cmd.Title.OnSuccess,
		Failed:  cmd.Title.OnFail,
	}, cmd.Context)
}

func (m *Handler) handleStagedProgressable(prog progress.StagedProgressable, title taskprogress.Title, context ...string) tea.Model {
	tsk := taskprogress.New(
		m.state.Running,
		taskprogress.WithStagedProgressable(prog),
	)
	tsk.HideProgressOnSuccess = true
	tsk.TitleOptions = title
	tsk.Context = context
	tsk.WindowSize = m.state.WindowSize

	return tsk
}
