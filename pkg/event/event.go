/*
Package event provides event types for all events that the library published onto the event bus. By convention, for each event
defined here there should be a corresponding event parser defined in the parsers/ child package.
*/
package event

import (
	"github.com/anchore/quill/internal"
	"github.com/wagoodman/go-partybus"
)

const (
	// Exit is a partybus event indicating the main process is to exit
	Exit partybus.EventType = internal.ApplicationName + "-exit-event"
)
