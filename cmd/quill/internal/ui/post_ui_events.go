package ui

import (
	"fmt"
	"os"
	"strings"

	"github.com/charmbracelet/lipgloss"
	"github.com/wagoodman/go-partybus"

	"github.com/anchore/quill/internal/log"
	"github.com/anchore/quill/quill/event"
)

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
