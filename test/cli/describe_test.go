package cli

import (
	"fmt"
	"strings"
	"testing"

	"github.com/anchore/quill/internal/test"
	"github.com/anchore/quill/test/trait"
)

func Test_DescribeCommand(t *testing.T) {
	tests := []struct {
		name       string
		cfg        *runConfig
		args       []string
		asset      string
		assertions []trait.Assertion
	}{
		{
			name:  "can describe unsigned binary",
			asset: test.Asset(t, "hello"),
			assertions: []trait.Assertion{
				trait.AssertInStdout("64-bit MachO"),              // the file section shows basic info
				trait.AssertInStdout("this binary is not signed"), // gracefully handles unsigned binaries
				trait.AssertSuccessfulReturnCode,
			},
		},
		{
			name:  "can describe signed binary",
			asset: test.Asset(t, "hello_signed"),
			assertions: []trait.Assertion{
				trait.AssertInStdout("64-bit MachO"),          // the file section shows basic info
				trait.AssertInStdout("quill-test-hello"),      // CN of the signing cert (CMS block shown)
				trait.AssertInStdout("1.2.840.113549.1.1.11"), // signature alforithm used
				trait.AssertInStdout("(hidden)"),              // don't show details of each page
				trait.AssertNotInOutput("@0x1000"),            // don't show details of each page
				trait.AssertSuccessfulReturnCode,
			},
		},
		{
			name:  "can describe signed binary (with details)",
			args:  []string{"--detail"},
			asset: test.Asset(t, "hello_signed"),
			assertions: []trait.Assertion{
				trait.AssertInStdout("64-bit MachO"),          // the file section shows basic info
				trait.AssertInStdout("quill-test-hello"),      // CN of the signing cert (CMS block shown)
				trait.AssertInStdout("1.2.840.113549.1.1.11"), // signature algorithm used
				trait.AssertNotInOutput("(hidden)"),           // show details of each page
				trait.AssertInStdout("@0x1000"),               // show details of each page
				trait.AssertSuccessfulReturnCode,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var cfgs []runConfig
			if tt.cfg != nil {
				cfgs = append(cfgs, *tt.cfg)
			}

			cmd := fmt.Sprintf("describe %s", tt.asset)
			if len(tt.args) > 0 {
				cmd += " " + strings.Join(tt.args, " ")
			}

			stdout, stderr, err := runQuill(t, cmd, cfgs...)
			checkAssertions(t, stdout, stderr, err, tt.assertions...)
		})
	}
}
