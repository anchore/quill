package ui

import (
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/wagoodman/go-partybus"

	"github.com/anchore/bubbly/bubbles/frame"
	"github.com/anchore/clio"
	"github.com/anchore/go-logger"
	handler "github.com/anchore/quill/cmd/quill/cli/ui"
	"github.com/anchore/quill/internal/bus"
	"github.com/anchore/quill/internal/log"
	"github.com/anchore/quill/quill/event"
)

var _ interface {
	tea.Model
	partybus.Responder
	clio.UI
} = (*UI)(nil)

type UI struct {
	program        *tea.Program
	running        *sync.WaitGroup
	quiet          bool
	subscription   partybus.Unsubscribable
	finalizeEvents []partybus.Event

	handler *handler.Handler
	frame   tea.Model
}

func New(_, quiet bool) *UI {
	h := handler.New()
	return &UI{
		handler: h,
		frame:   frame.New(),
		running: &sync.WaitGroup{},
		quiet:   quiet,
	}
}

func (m *UI) Setup(subscription partybus.Unsubscribable) error {
	// we still want to collect log messages, however, we also the logger shouldn't write to the screen directly
	if logWrapper, ok := log.Get().(logger.Controller); ok {
		logWrapper.SetOutput(m.frame.(*frame.Frame).Footer())
	}

	m.subscription = subscription
	m.program = tea.NewProgram(m, tea.WithOutput(os.Stderr), tea.WithInput(os.Stdin))
	m.running.Add(1)

	go func() {
		defer m.running.Done()
		if _, err := m.program.Run(); err != nil {
			log.Errorf("unable to start UI: %+v", err)
			m.exit()
		}
	}()

	return nil
}

func (m *UI) exit() {
	// stop the event loop
	bus.Exit()
}

func (m *UI) Handle(e partybus.Event) error {
	if m.program != nil {
		m.program.Send(e)
		if e.Type == event.CLIExitType {
			return m.subscription.Unsubscribe()
		}
	}
	return nil
}

func (m *UI) Teardown(force bool) error {
	if !force {
		m.handler.State().Running.Wait()
		m.program.Quit()
		// typically in all cases we would want to wait for the UI to finish. However there are still error cases
		// that are not accounted for, resulting in hangs. For now, we'll just wait for the UI to finish in the
		// happy path only. There will always be an indication of the problem to the user via reporting the error
		// string from the worker (outside of the UI after teardown).
		m.running.Wait()
	} else {
		_ = runWithTimeout(250*time.Millisecond, func() error {
			m.handler.State().Running.Wait()
			return nil
		})

		// it may be tempting to use Kill() however it has been found that this can cause the terminal to be left in
		// a bad state (where Ctrl+C and other control characters no longer works for future processes in that terminal).
		m.program.Quit()

		_ = runWithTimeout(250*time.Millisecond, func() error {
			m.running.Wait()
			return nil
		})
	}

	// TODO: allow for writing out the full log output to the screen (only a partial log is shown currently)
	// this needs coordination to know what the last frame event is to change the state accordingly (which isn't possible now)

	postUIEvents(m.quiet, m.finalizeEvents...)

	return nil
}

// bubbletea.Model functions

func (m UI) Init() tea.Cmd {
	return m.frame.Init()
}

func (m UI) RespondsTo() []partybus.EventType {
	return append([]partybus.EventType{
		event.CLIReportType,
		event.CLINotificationType,
		event.CLIExitType,
	}, m.handler.RespondsTo()...)
}

func (m *UI) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	// note: we need a pointer receiver such that the same instance of UI used in Teardown is referenced (to keep finalize events)

	var cmds []tea.Cmd

	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "esc", "ctrl+c":
			m.exit()
			return m, tea.Quit
		}

	case partybus.Event:
		switch msg.Type {
		case event.CLIReportType, event.CLINotificationType, event.CLIExitType:
			// keep these for when the UI is terminated to show to the screen (or perform other events)
			m.finalizeEvents = append(m.finalizeEvents, msg)

			// why not return tea.Quit here for exit events? because there may be UI components that still need the update-render loop.
			// for this reason we'll let the quill event loop call Teardown() which will explicitly wait for these components
			return m, nil
		}

		for _, newModel := range m.handler.Handle(msg) {
			if newModel == nil {
				continue
			}
			cmds = append(cmds, newModel.Init())
			m.frame.(*frame.Frame).AppendModel(newModel)
		}
		// intentionally fallthrough to update the frame model
	}

	frameModel, cmd := m.frame.Update(msg)
	m.frame = frameModel
	cmds = append(cmds, cmd)

	return m, tea.Batch(cmds...)
}

func (m UI) View() string {
	return m.frame.View()
}

func postUIEvents(quiet bool, events ...partybus.Event) {
	// TODO: add partybus event filter to filter down to events matching a type

	// show all accumulated reports to stdout
	var reports []string
	for _, e := range events {
		if e.Type != event.CLIReportType {
			continue
		}

		source, report, err := event.ParseCLIReportType(e)
		if err != nil {
			log.WithFields("error", err).
				Warn("failed to gather final report for %q", source)
		} else {
			// remove all whitespace padding from the end of the report
			reports = append(reports, strings.TrimRight(report, "\n ")+"\n")
		}
	}

	// prevent the double new-line at the end of the report
	fmt.Print(strings.Join(reports, "\n"))

	if !quiet {
		// show all notifications reports to stderr
		for _, e := range events {
			if e.Type != event.CLINotificationType {
				continue
			}

			source, notification, err := event.ParseCLINotificationType(e)
			if err != nil {
				log.WithFields("error", err).
					Warnf("failed to gather notification for %q", source)
			} else {
				// 13 = high intensity magenta (ANSI 16 bit code)
				_, _ = fmt.Fprintln(os.Stderr, lipgloss.NewStyle().Foreground(lipgloss.Color("13")).Render(notification))
			}
		}
	}
}

func runWithTimeout(timeout time.Duration, fn func() error) (err error) {
	c := make(chan struct{}, 1)
	go func() {
		err = fn()
		c <- struct{}{}
	}()
	select {
	case <-c:
	case <-time.After(timeout):
		return fmt.Errorf("timed out after %v", timeout)
	}
	return err
}
