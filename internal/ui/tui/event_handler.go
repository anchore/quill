package tui

import (
	tea "github.com/charmbracelet/bubbletea"
	"github.com/wagoodman/go-partybus"

	"github.com/anchore/quill/quill/event"
)

func (m *UI) eventHandler(e partybus.Event) (tea.Model, tea.Cmd) {
	switch e.Type {
	case event.Report, event.Notification, event.Exit:
		// keep these for when the UI is terminated to show to the screen (or perform other events)
		m.finalize = append(m.finalize, e)

		// why not return tea.Quit here for exit events? because there may be UI components that still need the update-render loop.
		// for this reason we'll let the quill event loop call Teardown() which will explicitly wait for these components
		return m, nil
	case event.InputPrompt:
		return m.handleInputPrompt(e)
	case event.Task:
		return m.handleTask(e)
	default:
		// TODO: type assert progressable and stager objects generically?
	}
	return m, nil
}
