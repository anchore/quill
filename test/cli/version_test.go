package cli

import (
	"testing"

	"github.com/anchore/quill/test/trait"
)

func Test_VersionCommand(t *testing.T) {
	tests := []struct {
		name       string
		command    string
		assertions []trait.Assertion
	}{
		{
			name:    "text output",
			command: "version",
			assertions: []trait.Assertion{
				trait.AssertInStdout("Application:"),
				trait.AssertInStdout("Version:"),
				trait.AssertSuccessfulReturnCode,
			},
		},
		{
			name:    "json output",
			command: "version -o json",
			assertions: []trait.Assertion{
				trait.AssertJSONReport,
				trait.AssertInStdout(`"application"`),
				trait.AssertInStdout(`"version"`),
				trait.AssertSuccessfulReturnCode,
			},
		},
		{
			name:    "root command short version output",
			command: "--version",
			assertions: []trait.Assertion{
				trait.AssertInStdout(`quill `),
				trait.AssertSuccessfulReturnCode,
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			stdout, stderr, err := runQuill(t, test.command)
			checkAssertions(t, stdout, stderr, err, test.assertions...)
		})
	}
}
