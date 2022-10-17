/*
Package event provides event types for all events that the library published onto the event bus. By convention, for each event
defined here there should be a corresponding event parser defined in the parsers/ child package.
*/
package event

import (
	"github.com/wagoodman/go-partybus"

	"github.com/anchore/quill/internal"
)

const (
	prefix = internal.ApplicationName

	// Exit is a partybus event indicating the main process is to exit
	Exit partybus.EventType = prefix + "-exit-event"

	Report       partybus.EventType = prefix + "-report"
	Notification partybus.EventType = prefix + "-notification"
	InputPrompt  partybus.EventType = prefix + "-input-prompt"
	Task         partybus.EventType = prefix + "-task"
)
