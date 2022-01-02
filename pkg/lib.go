package pkg

import (
	"github.com/wagoodman/go-partybus"
	"github.com/wagoodman/quill/internal/bus"
	"github.com/wagoodman/quill/internal/log"
	"github.com/wagoodman/quill/pkg/logger"
)

// SetLogger sets the logger object used for all logging calls.
func SetLogger(logger logger.Logger) {
	log.Log = logger
}

// SetBus sets the event bus for all library bus publish events onto (in-library subscriptions are not allowed).
func SetBus(b *partybus.Bus) {
	bus.SetPublisher(b)
}
