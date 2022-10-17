package taskprogress

import (
	"errors"
	"sync"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/gkampitakis/go-snaps/snaps"
	"github.com/stretchr/testify/require"
	"github.com/wagoodman/go-progress"

	"github.com/anchore/quill/internal/ui/tui/bubbles/testutil"
)

func subject(t testing.TB) (*progress.Manual, *progress.Stage, Model) {
	prog := &progress.Manual{
		N:     40,
		Total: -1,
		Err:   nil,
	}
	stage := &progress.Stage{
		Current: "working",
	}

	tsk := New(
		&sync.WaitGroup{},
		WithStagedProgressable(progress.StagedProgressable(&struct {
			progress.Stager
			progress.Progressable
		}{
			Stager:       stage,
			Progressable: prog,
		})),
		WithNoStyle(),
	)
	tsk.HideProgressOnSuccess = true
	tsk.TitleOptions = Title{
		Default: "Do work",
		Running: "Doing work",
		Success: "Did work",
		Failed:  "Failed at work :(",
	}
	tsk.Context = []string{
		"at home",
	}
	tsk.WindowSize = tea.WindowSizeMsg{
		Width:  100,
		Height: 60,
	}

	return prog, stage, tsk
}

func subjectGen(t testing.TB) Model {
	_, _, tsk := subject(t)
	return tsk
}

func TestModel_View(t *testing.T) {

	tests := []struct {
		name       string
		taskGen    func(testing.TB) Model
		iterations int
	}{
		{
			name: "in progress without progress bar",
			taskGen: func(tb testing.TB) Model {
				prog, _, tsk := subject(t)
				prog.N, prog.Total = 40, -1
				return tsk
			},
		},
		{
			name: "in progress with progress bar",
			taskGen: func(tb testing.TB) Model {
				prog, _, tsk := subject(t)
				prog.N, prog.Total = 40, 100
				return tsk
			},
		},
		{
			name: "successfully finished hides progress bar",
			taskGen: func(tb testing.TB) Model {
				prog, stage, tsk := subject(t)
				// note: we set progress to have a total size to ensure it is hidden
				prog.N, prog.Total = 100, 100
				stage.Current = "done!"
				return tsk
			},
		},
		{
			name: "successfully finished keeps progress bar shown",
			taskGen: func(tb testing.TB) Model {
				prog, stage, tsk := subject(t)
				tsk.HideProgressOnSuccess = false
				// note: we set progress to have a total size to ensure it is hidden
				prog.N, prog.Total = 100, 100
				stage.Current = "done!"
				return tsk
			},
		},
		{
			name: "no context",
			taskGen: func(tb testing.TB) Model {
				_, _, tsk := subject(t)
				tsk.Context = nil
				return tsk
			},
		},

		{
			name: "multiple hints",
			taskGen: func(tb testing.TB) Model {
				_, _, tsk := subject(t)
				tsk.Hints = []string{"info++", "info!++"}
				return tsk
			},
		},
		{
			name: "error",
			taskGen: func(tb testing.TB) Model {
				prog, _, tsk := subject(t)
				prog.SetCompleted()
				prog.Err = errors.New("woops")
				return tsk
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var m tea.Model = tt.taskGen(t)
			tsk, ok := m.(Model)
			require.True(t, ok)
			got := testutil.RunModel(t, tsk, tt.iterations, TickMsg{
				Time:     time.Now(),
				sequence: tsk.sequence,
				ID:       tsk.id,
			})
			t.Log(got)
			snaps.MatchSnapshot(t, got)
		})
	}
}
