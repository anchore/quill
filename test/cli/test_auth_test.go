package cli

import (
	"testing"

	"github.com/anchore/quill/test/trait"
)

func Test_TestAuthCommand(t *testing.T) {
	tests := []struct {
		name       string
		command    string
		assertions []trait.Assertion
	}{
		{
			name:    "help output",
			command: "test-auth --help",
			assertions: []trait.Assertion{
				trait.AssertInStdout("test Apple notarization credentials"),
				trait.AssertInStdout("FORBIDDEN.REQUIRED_AGREEMENTS_MISSING_OR_EXPIRED"),
				trait.AssertSuccessfulReturnCode,
			},
		},
		{
			name:    "ad-hoc signing fails notarization check",
			command: "test-auth --ad-hoc",
			assertions: []trait.Assertion{
				trait.AssertInStderr("binary is not signed thus will not pass notarization"),
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
