package ui

import (
	"os"

	"golang.org/x/term"

	"github.com/anchore/quill/internal/ui/loggerui"
	"github.com/anchore/quill/internal/ui/tui"
)

// Select is responsible for determining the specific UI function given select user option, the current platform
// config values, and environment status (such as a TTY being present). The first UI in the returned slice of UIs
// is intended to be used and the UIs that follow are meant to be attempted only in a fallback posture when there
// are environmental problems (e.g. cannot write to the terminal). A writer is provided to capture the output of
// the final SBOM report.
func Select(cfg Config) (uis []UI) {
	isStdoutATty := term.IsTerminal(int(os.Stdout.Fd()))
	isStderrATty := term.IsTerminal(int(os.Stderr.Fd()))
	notATerminal := !isStderrATty && !isStdoutATty
	switch {
	case cfg.Verbose || cfg.Quiet || notATerminal || !isStderrATty:
		uis = append(uis, loggerui.New(cfg.Debug, cfg.Quiet))
	default:
		uis = append(uis, tui.New(cfg.Debug, cfg.Quiet), loggerui.New(cfg.Debug, cfg.Quiet))
	}

	return uis

	// return []UI{loggerui.New(cfg.Debug, cfg.Quiet)}
}
