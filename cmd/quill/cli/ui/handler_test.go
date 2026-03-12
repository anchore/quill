package ui

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// mockCanceller implements the Cancel() interface for testing
type mockCanceller struct {
	cancelled bool
}

func (m *mockCanceller) IsSensitive() bool       { return false }
func (m *mockCanceller) PromptMessage() string   { return "test" }
func (m *mockCanceller) Respond(_ string) error  { return nil }
func (m *mockCanceller) Validate(_ string) error { return nil }
func (m *mockCanceller) Cancel()                 { m.cancelled = true }

// mockNonCanceller implements PromptWriter but not Cancel()
type mockNonCanceller struct{}

func (m *mockNonCanceller) IsSensitive() bool       { return false }
func (m *mockNonCanceller) PromptMessage() string   { return "test" }
func (m *mockNonCanceller) Respond(_ string) error  { return nil }
func (m *mockNonCanceller) Validate(_ string) error { return nil }

func TestHandler_CancelPrompt_CallsCancelOnActivePrompt(t *testing.T) {
	h := New()
	mock := &mockCanceller{}
	h.state.activePrompt = mock

	h.CancelPrompt()

	assert.True(t, mock.cancelled, "Cancel() should have been called")
	assert.Nil(t, h.state.activePrompt, "activePrompt should be cleared")
}

func TestHandler_CancelPrompt_ClearsActivePrompt(t *testing.T) {
	h := New()
	mock := &mockCanceller{}
	h.state.activePrompt = mock

	h.CancelPrompt()

	assert.Nil(t, h.state.activePrompt)
}

func TestHandler_CancelPrompt_HandlesNilActivePrompt(t *testing.T) {
	h := New()
	h.state.activePrompt = nil

	// should not panic
	assert.NotPanics(t, func() {
		h.CancelPrompt()
	})
}

func TestHandler_CancelPrompt_HandlesNonCancellablePrompt(t *testing.T) {
	h := New()
	mock := &mockNonCanceller{}
	h.state.activePrompt = mock

	// should not panic when prompt doesn't implement Cancel()
	assert.NotPanics(t, func() {
		h.CancelPrompt()
	})

	// activePrompt should still be cleared
	assert.Nil(t, h.state.activePrompt)
}

func TestNew_InitializesState(t *testing.T) {
	h := New()

	assert.NotNil(t, h.state)
	assert.NotNil(t, h.state.Running)
	assert.Nil(t, h.state.activePrompt)
}
