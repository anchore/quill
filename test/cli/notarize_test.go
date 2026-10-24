package cli

import (
	"testing"

	"github.com/anchore/quill/test/trait"
)

func Test_MissingNotaryCredentials(t *testing.T) {
	tests := []struct {
		name       string
		command    string
		assertions []trait.Assertion
	}{
		{
			name:    "notarize fails without credentials",
			command: "notarize /nonexistent/binary",
			assertions: []trait.Assertion{
				trait.AssertInStderr("notarization credentials required"),
				trait.AssertFailingReturnCode,
			},
		},
		{
			name:    "notarize fails with a partial set of credentials",
			command: "notarize /nonexistent/binary --notary-issuer issuer --notary-key-id key-id",
			assertions: []trait.Assertion{
				trait.AssertInStderr("notarization credentials required"),
				trait.AssertFailingReturnCode,
			},
		},
		{
			name:    "sign-and-notarize fails before signing without credentials",
			command: "sign-and-notarize /nonexistent/binary --ad-hoc",
			assertions: []trait.Assertion{
				trait.AssertInStderr("notarization credentials required"),
				trait.AssertNotInOutput("signing failed"),
				trait.AssertFailingReturnCode,
			},
		},
		{
			name:    "submission list fails without credentials",
			command: "submission list",
			assertions: []trait.Assertion{
				trait.AssertInStderr("notarization credentials required"),
				trait.AssertFailingReturnCode,
			},
		},
		{
			name:    "submission status fails without credentials",
			command: "submission status some-id",
			assertions: []trait.Assertion{
				trait.AssertInStderr("notarization credentials required"),
				trait.AssertFailingReturnCode,
			},
		},
		{
			name:    "submission logs fails without credentials",
			command: "submission logs some-id",
			assertions: []trait.Assertion{
				trait.AssertInStderr("notarization credentials required"),
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
