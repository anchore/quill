package frame

import (
	"bytes"
	"fmt"
	"io"
	"strings"

	tea "github.com/charmbracelet/bubbletea"

	handler "github.com/anchore/quill/cmd/quill/cli/ui"
)

type Frame struct {
	footer         *bytes.Buffer
	models         []tea.Model
	state          *handler.State
	showFooter     bool
	truncateFooter bool
}

func New(state *handler.State) *Frame {
	return &Frame{
		footer:         &bytes.Buffer{},
		state:          state,
		showFooter:     true,
		truncateFooter: true,
	}
}

func (f Frame) Footer() io.ReadWriter {
	return f.footer
}

func (f *Frame) ShowFooter(set bool) {
	f.showFooter = set
}

func (f *Frame) TruncateFooter(set bool) {
	f.truncateFooter = set
}

func (f *Frame) AppendModel(uiElement tea.Model) {
	f.models = append(f.models, uiElement)
}

func (f *Frame) State() *handler.State {
	return f.state
}

func (f Frame) Init() tea.Cmd {
	return nil
}

func (f *Frame) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	// note: we need a pointer receiver such that the same instance of UI used in Teardown is referenced (to keep finalize events)

	if msg, ok := msg.(tea.WindowSizeMsg); ok {
		f.state.WindowSize = msg
	}

	var cmds []tea.Cmd
	for i, el := range f.models {
		newEl, cmd := el.Update(msg)
		cmds = append(cmds, cmd)
		f.models[i] = newEl
	}
	return f, tea.Batch(cmds...)
}

func (f Frame) View() string {
	// all UI elements
	str := ""
	for _, p := range f.models {
		rendered := p.View()
		if len(rendered) > 0 {
			str += rendered + "\n"
		}
	}

	// log events
	if f.showFooter {
		contents := f.footer.String()
		if f.truncateFooter {
			logLines := strings.Split(contents, "\n")
			logMax := f.state.WindowSize.Height - strings.Count(str, "\n")
			trimLog := len(logLines) - logMax
			if trimLog > 0 && len(logLines) >= trimLog {
				logLines = logLines[trimLog:]
			}
			for _, line := range logLines {
				if len(line) > 0 {
					str += fmt.Sprintf("%s\n", line)
				}
			}
		} else {
			str += contents
		}
	}
	return str
}
