package taskprogress

import (
	"time"
)

// TickMsg indicates that the timer has ticked and we should render a frame.
type TickMsg struct {
	Time     time.Time
	sequence int
	ID       int
}
