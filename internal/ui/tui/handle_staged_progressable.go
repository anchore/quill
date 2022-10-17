package tui

import (
	tea "github.com/charmbracelet/bubbletea"
	"github.com/wagoodman/go-progress"

	"github.com/anchore/quill/internal/ui/tui/bubbles/taskprogress"
)

func (m *UI) handleStagedProgressable(prog progress.StagedProgressable, title taskprogress.Title, context ...string) (tea.Model, tea.Cmd) {
	tsk := taskprogress.New(
		m.liveComponents,
		taskprogress.WithStagedProgressable(prog),
	)
	tsk.HideProgressOnSuccess = true
	tsk.TitleOptions = title
	tsk.Context = context
	tsk.WindowSize = m.windowSize

	m.uiElements = append(m.uiElements, tsk)

	return m, tsk.Init()
}
