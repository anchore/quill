package main

import (
	"context"
	"os"
	"os/signal"

	"github.com/anchore/quill/cmd/quill/cli"
	"github.com/anchore/quill/internal/log"
	"github.com/anchore/quill/internal/utils"
)

func main() {
	cmd := cli.New()

	// drive application control from a single context which can be cancelled (notifying the event loop to stop)
	ctx, cancel := context.WithCancel(context.Background())
	cmd.SetContext(ctx)

	// note: it is important to always do signal handling from the main package. In this way if quill is used
	// as a lib a refactor would not need to be done (since anything from the main package cannot be imported this
	// nicely enforces this constraint)
	signals := make(chan os.Signal, 10) // Note: A buffered channel is recommended for this; see https://golang.org/pkg/os/signal/#Notify
	signal.Notify(signals, os.Interrupt)

	defer func() {
		signal.Stop(signals)
		cancel()
	}()

	go func() {
		select {
		case <-signals: // first signal, cancel context
			log.Trace("signal interrupt, stop requested")
			cancel()
		case <-ctx.Done():
		}
		<-signals // second signal, hard exit
		log.Trace("signal interrupt, killing")
		os.Exit(1)
	}()

	utils.FatalOnError(cmd.Execute(), "error")
}
