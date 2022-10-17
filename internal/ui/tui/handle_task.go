package tui

import (
	tea "github.com/charmbracelet/bubbletea"
	"github.com/wagoodman/go-partybus"

	"github.com/anchore/quill/internal/log"
	"github.com/anchore/quill/internal/ui/tui/bubbles/taskprogress"
	"github.com/anchore/quill/quill/event/parser"
)

func (m *UI) handleTask(e partybus.Event) (tea.Model, tea.Cmd) {
	cmd, prog, err := parser.Task(e)
	if err != nil {
		log.Warnf("unable to parse event: %+v", err)
		return m, nil
	}

	return m.handleStagedProgressable(prog, taskprogress.Title{
		Default: cmd.Title.Default,
		Running: cmd.Title.WhileRunning,
		Success: cmd.Title.OnSuccess,
		Failed:  cmd.Title.OnFail,
	}, cmd.Context)
}
