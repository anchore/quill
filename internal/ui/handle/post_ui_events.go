package handle

import (
	"fmt"
	"os"
	"strings"

	"github.com/charmbracelet/lipgloss"
	"github.com/wagoodman/go-partybus"

	"github.com/anchore/quill/internal/log"
	"github.com/anchore/quill/quill/event"
	"github.com/anchore/quill/quill/event/parser"
)

func PostUIEvents(quiet bool, events ...partybus.Event) {
	// TODO: add partybus event filter to filter down to events matching a type

	// show all accumulated reports to stdout
	var reports []string
	for _, e := range events {
		if e.Type != event.Report {
			continue
		}

		source, report, err := parser.Report(e)
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
			if e.Type != event.Notification {
				continue
			}

			source, notification, err := parser.Notification(e)
			if err != nil {
				log.WithFields("error", err).
					Warnf("failed to gather notification for %q", source)
			} else {
				// 13 = high intensity magenta (ANSI 16 bit code)
				_, _ = fmt.Fprintln(os.Stderr, lipgloss.NewStyle().Foreground(lipgloss.Color("13")).Render(notification))
			}
		}
	}

	// run exit finalizers
	for _, e := range events {
		switch e.Type {
		case event.Exit:
			if err := Exit(e); err != nil {
				log.WithFields("error", err).
					Warn("failed to handle exit event gracefully")
			}
		// TODO: add more supported finalizer events...
		default:
			continue
		}
	}
}
