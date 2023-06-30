package ui

import (
	"sync"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/wagoodman/go-partybus"
	"github.com/wagoodman/go-progress"

	"github.com/anchore/bubbly"
	"github.com/anchore/bubbly/bubbles/prompt"
	"github.com/anchore/bubbly/bubbles/taskprogress"
	"github.com/anchore/quill/internal/log"
	"github.com/anchore/quill/quill/event"
)

var _ bubbly.EventHandler = (*Handler)(nil)

type Handler struct {
	state *State
	bubbly.EventHandler
}

type State struct {
	WindowSize tea.WindowSizeMsg
	Running    *sync.WaitGroup
}

func New() *Handler {
	d := bubbly.NewEventDispatcher()

	h := &Handler{
		EventHandler: d,
		state: &State{
			Running: &sync.WaitGroup{},
		},
	}

	d.AddHandlers(map[partybus.EventType]bubbly.EventHandlerFn{
		event.CLIInputPromptType: h.handleInputPrompt,
		event.TaskType:           h.handleTask,
	})

	return h
}

func (m *Handler) State() *State {
	return m.state
}

func (m *Handler) handleInputPrompt(e partybus.Event) []tea.Model {
	writer, err := event.ParseCLIInputPromptType(e)
	if err != nil {
		log.Warnf("unable to parse event: %+v", err)
		return nil
	}

	return []tea.Model{prompt.New(writer)}
}

func (m *Handler) handleTask(e partybus.Event) []tea.Model {
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

func (m *Handler) handleStagedProgressable(prog progress.StagedProgressable, title taskprogress.Title, context ...string) []tea.Model {
	tsk := taskprogress.New(
		m.state.Running,
		taskprogress.WithStagedProgressable(prog),
	)
	tsk.HideProgressOnSuccess = true
	tsk.TitleOptions = title
	tsk.Context = context
	tsk.WindowSize = m.state.WindowSize

	return []tea.Model{tsk}
}
