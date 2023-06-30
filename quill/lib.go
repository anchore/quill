package quill

import (
	"github.com/anchore/go-logger/adapter/redact"
	"github.com/wagoodman/go-partybus"

	"github.com/anchore/go-logger"
	"github.com/anchore/quill/internal/bus"
	"github.com/anchore/quill/internal/log"
	intRedact "github.com/anchore/quill/internal/redact"
)

// SetLogger sets the logger object used for all logging calls.
func SetLogger(logger logger.Logger) {
	log.Set(logger)
}

// SetBus sets the event bus for all library bus publish events onto (in-library subscriptions are not allowed).
func SetBus(b *partybus.Bus) {
	bus.Set(b)
}

func SetRedactStore(store redact.Store) {
	intRedact.Set(store)
}
