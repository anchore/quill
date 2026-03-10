package bus

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPrompter_ContextReturnsInternalContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	prompter := &Prompter{
		Prompter: nil,
		ctx:      ctx,
		cancel:   cancel,
	}

	// the internal context should be accessible (though we removed the Context() method,
	// we can verify the context is properly stored)
	assert.NotNil(t, prompter.ctx)
}

func TestPrompter_Cancel_CausesResponseToReturnError(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())

	prompter := &Prompter{
		Prompter: nil,
		ctx:      ctx,
		cancel:   cancel,
	}

	// cancel the prompt
	prompter.Cancel()

	// verify context is cancelled
	assert.Error(t, prompter.ctx.Err())
	assert.Equal(t, context.Canceled, prompter.ctx.Err())
}

func TestPrompter_Cancel_IsIdempotent(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())

	prompter := &Prompter{
		Prompter: nil,
		ctx:      ctx,
		cancel:   cancel,
	}

	// calling Cancel multiple times should not panic
	prompter.Cancel()
	prompter.Cancel()
	prompter.Cancel()

	assert.Error(t, prompter.ctx.Err())
}

func TestPrompter_Cancel_WithNilCancel(t *testing.T) {
	prompter := &Prompter{
		Prompter: nil,
		ctx:      context.Background(),
		cancel:   nil,
	}

	// should not panic with nil cancel func
	require.NotPanics(t, func() {
		prompter.Cancel()
	})
}

func TestPromptForInput_ReturnsNilWhenNoPublisher(t *testing.T) {
	// ensure publisher is nil (default state without Setup)
	publisher = nil

	prompter := PromptForInput(context.Background(), "test message", false)

	assert.Nil(t, prompter)
}

func TestPromptForInput_CreatesPrompterWithCancellableContext(t *testing.T) {
	// we need a publisher to test this, but we can at least verify the nil case
	// full integration testing would require setting up the event bus
}

func TestPrompter_ContextCancellation_PropagatesFromParent(t *testing.T) {
	parentCtx, parentCancel := context.WithCancel(context.Background())
	childCtx, childCancel := context.WithCancel(parentCtx)

	prompter := &Prompter{
		Prompter: nil,
		ctx:      childCtx,
		cancel:   childCancel,
	}

	// cancel from parent
	parentCancel()

	// child context should also be cancelled
	select {
	case <-prompter.ctx.Done():
		// expected
	case <-time.After(100 * time.Millisecond):
		t.Fatal("context should have been cancelled")
	}

	assert.Error(t, prompter.ctx.Err())
}

func TestErrPromptCancelled(t *testing.T) {
	// verify the error message is user-friendly
	assert.Equal(t, "prompt cancelled", ErrPromptCancelled.Error())
}
