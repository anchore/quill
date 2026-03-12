package ui

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"strings"

	"github.com/wagoodman/go-partybus"
	"golang.org/x/term"

	"github.com/anchore/clio"
	"github.com/anchore/quill/quill/event"
)

var _ clio.UI = (*NoUI)(nil)

type NoUI struct {
	finalizeEvents []partybus.Event
	subscription   partybus.Unsubscribable
}

func None() *NoUI {
	return &NoUI{}
}

func (n *NoUI) Setup(subscription partybus.Unsubscribable) error {
	n.subscription = subscription
	return nil
}

func (n *NoUI) Handle(e partybus.Event) error {
	switch e.Type {
	case event.CLIReportType, event.CLINotificationType:
		// keep these for when the UI is terminated to show to the screen (or perform other events)
		n.finalizeEvents = append(n.finalizeEvents, e)
	case event.CLIInputPromptType:
		return n.handleInputPrompt(e)
	case event.CLIExitType:
		return n.subscription.Unsubscribe()
	}
	return nil
}

var errPromptCancelled = errors.New("prompt cancelled")

func (n *NoUI) handleInputPrompt(e partybus.Event) error {
	writer, err := event.ParseCLIInputPromptType(e)
	if err != nil {
		return fmt.Errorf("unable to parse prompt event: %w", err)
	}

	// print prompt to stderr
	fmt.Fprint(os.Stderr, writer.PromptMessage())
	if !strings.HasSuffix(writer.PromptMessage(), " ") {
		fmt.Fprint(os.Stderr, " ")
	}

	input, err := n.readInput(writer.IsSensitive())
	if err != nil {
		return err
	}

	if err := writer.Validate(input); err != nil {
		return fmt.Errorf("invalid input: %w", err)
	}

	return writer.Respond(input)
}

func (n *NoUI) readInput(sensitive bool) (string, error) {
	// set up signal handling for Ctrl+C
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt)
	defer signal.Stop(sigChan)

	resultChan := make(chan string, 1)
	errChan := make(chan error, 1)

	go func() {
		if sensitive {
			// hide sensitive input (passwords)
			byteInput, err := term.ReadPassword(int(os.Stdin.Fd()))
			if err != nil {
				errChan <- fmt.Errorf("unable to read password: %w", err)
				return
			}
			fmt.Fprintln(os.Stderr) // newline after hidden input
			resultChan <- string(byteInput)
		} else {
			scanner := bufio.NewScanner(os.Stdin)
			if scanner.Scan() {
				resultChan <- scanner.Text()
				return
			}
			if err := scanner.Err(); err != nil {
				errChan <- fmt.Errorf("unable to read input: %w", err)
				return
			}
			// EOF without error (e.g., piped empty input)
			resultChan <- ""
		}
	}()

	select {
	case <-sigChan:
		fmt.Fprintln(os.Stderr) // newline after ^C
		return "", errPromptCancelled
	case err := <-errChan:
		return "", err
	case input := <-resultChan:
		return input, nil
	}
}

func (n NoUI) Teardown(_ bool) error {
	postUIEvents(false, n.finalizeEvents...)
	return nil
}
