package cli

import (
	"fmt"
	"testing"

	"github.com/anchore/quill/internal/test"
	"github.com/anchore/quill/test/trait"
)

func Test_P12DescribeCommand(t *testing.T) {
	tests := []struct {
		name       string
		cfg        *runConfig
		asset      string
		assertions []trait.Assertion
	}{
		{
			name: "can describe p12",
			cfg: &runConfig{
				env: map[string]string{
					// from internal/test/fixture-hello/Makefile
					"QUILL_P12_PASSWORD": "TopsyKretts",
				},
			},
			asset: test.Asset(t, "hello.p12"),
			assertions: []trait.Assertion{
				trait.AssertInStdout("rsa.PrivateKey exists"),  // private key exists
				trait.AssertInStdout("quill-test-hello"),       // describes signing certificate
				trait.AssertInStdout("Certificate Chain: (0)"), // shows no chain
				trait.AssertSuccessfulReturnCode,
			},
		},
		{
			name: "can describe p12 with chain",
			cfg: &runConfig{
				env: map[string]string{
					// from internal/test/fixture-chain/Makefile
					"QUILL_P12_PASSWORD": "123456",
				},
			},
			asset: test.Asset(t, "chain.p12"),
			assertions: []trait.Assertion{
				trait.AssertInStdout("rsa.PrivateKey exists"),      // private key exists
				trait.AssertInStdout("quill-test-leaf"),            // describes signing certificate
				trait.AssertInStdout("Certificate Chain: (2)"),     // shows no chain
				trait.AssertInStdout("quill-test-intermediate-ca"), // intermediate cert
				trait.AssertInStdout("quill-test-root-ca"),         // root cert
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
			stdout, stderr, err := runQuill(t, fmt.Sprintf("p12 describe %s", tt.asset), cfgs...)
			checkAssertions(t, stdout, stderr, err, tt.assertions...)
		})
	}
}
