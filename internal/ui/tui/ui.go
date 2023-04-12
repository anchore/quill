package tui

import (
	"bytes"
	"fmt"
	"os"
	"strings"
	"sync"

	"github.com/charmbracelet/bubbles/spinner"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/wagoodman/go-partybus"

	"github.com/anchore/go-logger"
	"github.com/anchore/quill/internal/bus"
	"github.com/anchore/quill/internal/log"
	"github.com/anchore/quill/internal/ui/handle"
	"github.com/anchore/quill/quill/event"
)

var _ tea.Model = (*UI)(nil)

type UI struct {
	program        *tea.Program
	logBuffer      *bytes.Buffer
	windowSize     tea.WindowSizeMsg
	uiElements     []tea.Model
	liveComponents *sync.WaitGroup
	finalize       []partybus.Event
	unsubscribe    func() error
	running        *sync.WaitGroup
	quiet          bool
}

func New(_, quiet bool) *UI {
	s := spinner.New()
	s.Spinner = spinner.MiniDot
	s.Style = lipgloss.NewStyle().Foreground(lipgloss.Color("205"))
	return &UI{
		liveComponents: &sync.WaitGroup{},
		running:        &sync.WaitGroup{},
		quiet:          quiet,
	}
}

func (m *UI) Setup(unsubscribe func() error) error {
	// we still want to collect log messages, however, we also the logger shouldn't write to the screen directly
	m.logBuffer = &bytes.Buffer{}
	if logWrapper, ok := log.Get().(logger.Controller); ok {
		logWrapper.SetOutput(m.logBuffer)
	}

	m.unsubscribe = unsubscribe
	m.program = tea.NewProgram(m, tea.WithOutput(os.Stderr), tea.WithInput(os.Stdin))
	m.running.Add(1)

	go func() {
		defer m.running.Done()
		if err := m.program.Start(); err != nil {
			log.Errorf("unable to start UI: %+v", err)
			m.exit()
		}
	}()

	return nil
}

func (m *UI) exit() {
	// stop the event loop
	bus.Publish(partybus.Event{
		Type: event.Exit,
	})
}

func (m *UI) Handle(e partybus.Event) error {
	if m.program != nil {
		m.program.Send(e)
		if e.Type == event.Exit {
			return m.unsubscribe()
		}
	}
	return nil
}

func (m *UI) Teardown(force bool) error {
	if !force {
		m.liveComponents.Wait()
		m.program.Quit()
	} else {
		m.program.Kill()
	}

	m.running.Wait()

	_, _ = os.Stderr.WriteString(m.logBuffer.String())

	handle.PostUIEvents(m.quiet, m.finalize...)

	return nil
}

// bubbletea.Model functions

func (m UI) Init() tea.Cmd {
	return nil
}

func (m *UI) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	// note: we need a pointer receiver such that the same instance of UI used in Teardown is referenced (to keep finalize events)

	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "esc", "ctrl+c":
			m.exit()
			return m, tea.Quit
		}

	case tea.WindowSizeMsg:
		m.windowSize = msg
		return m.updateUIElements(msg)

	case partybus.Event:
		return m.eventHandler(msg)
	}

	return m.updateUIElements(msg)
}

func (m *UI) updateUIElements(msg tea.Msg) (tea.Model, tea.Cmd) {
	// note: we need a pointer receiver such that the same instance of UI used in Teardown is referenced (to keep finalize events)

	var cmds []tea.Cmd
	for i, el := range m.uiElements {
		newEl, cmd := el.Update(msg)
		cmds = append(cmds, cmd)
		m.uiElements[i] = newEl
	}
	return m, tea.Batch(cmds...)
}

func (m UI) View() string {
	// all UI elements
	str := ""
	for _, p := range m.uiElements {
		str += p.View() + "\n"
	}

	// log events
	logLines := strings.Split(m.logBuffer.String(), "\n")
	logMax := m.windowSize.Height - strings.Count(str, "\n")
	trimLog := len(logLines) - logMax
	if trimLog > 0 && len(logLines) >= trimLog {
		logLines = logLines[trimLog:]
	}
	for _, line := range logLines {
		if len(line) > 0 {
			str += fmt.Sprintf("%s\n", line)
		}
	}
	return str
}
