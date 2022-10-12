package handle

import (
	"github.com/wagoodman/go-partybus"

	"github.com/anchore/quill/quill/event/parser"
)

// handleExit is a UI function for processing the Exit bus event,
// and calling the given function to output the contents.
func Exit(e partybus.Event) error {
	return parser.Exit(e)
}
