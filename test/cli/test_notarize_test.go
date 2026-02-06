package cli

import (
	"testing"

	"github.com/anchore/quill/test/trait"
)

func Test_TestNotarizeCommand(t *testing.T) {
	tests := []struct {
		name       string
		command    string
		assertions []trait.Assertion
	}{
		{
			name:    "help output",
			command: "test-notarize --help",
			assertions: []trait.Assertion{
				trait.AssertInStdout("Test Apple notarization credentials"),
				trait.AssertInStdout("FORBIDDEN.REQUIRED_AGREEMENTS_MISSING_OR_EXPIRED"),
				trait.AssertInStdout("5 minute timeout"),
				trait.AssertSuccessfulReturnCode,
			},
		},
		{
			name:    "missing notary credentials fails early",
			command: "test-notarize --ad-hoc",
			assertions: []trait.Assertion{
				trait.AssertInStderr("notarization credentials required"),
				trait.AssertFailingReturnCode,
			},
		},
		{
			name:    "missing notary credentials fails before p12 check",
			command: "test-notarize --p12 /nonexistent/file.p12",
			assertions: []trait.Assertion{
				trait.AssertInStderr("notarization credentials required"),
				trait.AssertFailingReturnCode,
			},
		},
		{
			name:    "rejects unexpected arguments",
			command: "test-notarize extra-arg",
			assertions: []trait.Assertion{
				trait.AssertInStderr("unknown command"),
				trait.AssertFailingReturnCode,
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
