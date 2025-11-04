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
				trait.AssertInStdout("test Apple notarization credentials"),
				trait.AssertInStdout("FORBIDDEN.REQUIRED_AGREEMENTS_MISSING_OR_EXPIRED"),
				trait.AssertInStdout("5 minute timeout"),
				trait.AssertSuccessfulReturnCode,
			},
		},
		{
			name:    "ad-hoc signing fails validation",
			command: "test-notarize --ad-hoc",
			assertions: []trait.Assertion{
				trait.AssertInStderr("ad-hoc signing cannot be used for notarization"),
				trait.AssertFailingReturnCode,
			},
		},
		{
			name:    "missing p12 file fails",
			command: "test-notarize --p12 /nonexistent/file.p12",
			assertions: []trait.Assertion{
				trait.AssertInStderr("unable to decode p12 file"),
				trait.AssertFailingReturnCode,
			},
		},
		{
			name:    "missing notary credentials fails",
			command: "test-notarize --p12 /tmp/fake.p12",
			assertions: []trait.Assertion{
				trait.AssertInStderr("issuer"),
				trait.AssertFailingReturnCode,
			},
		},
		{
			name:    "rejects unexpected arguments",
			command: "test-notarize extra-arg",
			assertions: []trait.Assertion{
				trait.AssertInStderr("accepts 0 arg(s), received 1"),
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
