/*
Package parsers provides parser helpers to extract payloads for each event type that the library publishes onto the event bus.
*/
package parsers

import (
	"fmt"

	"github.com/wagoodman/go-partybus"

	"github.com/anchore/quill/quill/event"
)

type ErrBadPayload struct {
	Type  partybus.EventType
	Field string
	Value interface{}
}

func (e *ErrBadPayload) Error() string {
	return fmt.Sprintf("event='%s' has bad event payload field='%v': '%+v'", string(e.Type), e.Field, e.Value)
}

func newPayloadErr(t partybus.EventType, field string, value interface{}) error {
	return &ErrBadPayload{
		Type:  t,
		Field: field,
		Value: value,
	}
}

func checkEventType(actual, expected partybus.EventType) error {
	if actual != expected {
		return newPayloadErr(expected, "Type", actual)
	}
	return nil
}

func ParseExitEvent(e partybus.Event) error {
	if err := checkEventType(e.Type, event.Exit); err != nil {
		return err
	}

	return nil
}
