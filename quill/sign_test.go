package quill

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/anchore/quill/internal/test"
)

func TestSign(t *testing.T) {

	type args struct {
		id                        string
		path                      string
		keyFile                   string
		keyPassword               string
		certFile                  string
		skipAssertAgainstCodesign bool
	}
	tests := []struct {
		name       string
		args       args
		assertions []test.OutputAssertion
	}{
		// TODO: add tests for multiple architectures
		{
			name: "ad-hoc sign the hello binary",
			args: args{
				id:   "hello-id",
				path: test.AssetCopy(t, "hello"),
			},
			assertions: []test.OutputAssertion{
				test.AssertContains("CodeDirectory v=20500 size=585 flags=0x2(adhoc) hashes=13+2 location=embedded"),
				test.AssertContains("Hash type=sha256 size=32"),
				test.AssertContains("CandidateCDHash sha256=564ecc61d055854d6b5a98c5559f91bb30f1e8c6"),
				test.AssertContains("CandidateCDHashFull sha256=564ecc61d055854d6b5a98c5559f91bb30f1e8c6aa57bec5782d6d49c623b475"),
				test.AssertContains("CDHash=564ecc61d055854d6b5a98c5559f91bb30f1e8c6"),
				test.AssertContains("CMSDigest=564ecc61d055854d6b5a98c5559f91bb30f1e8c6aa57bec5782d6d49c623b475"),
				test.AssertContains("CMSDigestType=2"),
				test.AssertContains("Signature=adhoc"),
				test.AssertContains("Info.plist=not bound"),
				test.AssertContains("TeamIdentifier=not set"),
				test.AssertContains("Sealed Resources=none"),
				test.AssertContains("Internal requirements count=1 size=48"),
			},
		},
		{
			name: "ad-hoc sign the syft binary (with a password)",
			args: args{
				id:   "syft-id",
				path: test.AssetCopy(t, "syft_unsigned"),
			},
			assertions: []test.OutputAssertion{
				test.AssertContains("CodeDirectory v=20500 size=208904 flags=0x2(adhoc) hashes=6523+2 location=embedded"),
				test.AssertContains("Hash type=sha256 size=32"),
				test.AssertContains("CandidateCDHash sha256=612acf7681e79dff0457551be60723b24d3ef576"),
				test.AssertContains("CandidateCDHashFull sha256=612acf7681e79dff0457551be60723b24d3ef576992fd1f582f039dcb166eb09"),
				test.AssertContains("CDHash=612acf7681e79dff0457551be60723b24d3ef576"),
				test.AssertContains("CMSDigest=612acf7681e79dff0457551be60723b24d3ef576992fd1f582f039dcb166eb09"),
				test.AssertContains("CMSDigestType=2"),
				test.AssertContains("Signature=adhoc"),
				test.AssertContains("Info.plist=not bound"),
				test.AssertContains("TeamIdentifier=not set"),
				test.AssertContains("Sealed Resources=none"),
				test.AssertContains("Internal requirements count=1 size=48"),
			},
		},
		{
			name: "sign the hello binary - single cert",
			args: args{
				id:       "my-id",
				path:     test.AssetCopy(t, "hello"),
				keyFile:  test.Asset(t, "hello-key.pem"),
				certFile: test.Asset(t, "hello-cert.pem"),
			},
			assertions: []test.OutputAssertion{
				test.AssertContains("CodeDirectory v=20500 size=582 flags=0x10000(runtime) hashes=13+2 location=embedded"),
				test.AssertContains("Hash type=sha256 size=32"),
				test.AssertContains("CandidateCDHash sha256=5638e77cca038d7ad72621c52ca393356e030e43"),
				test.AssertContains("CandidateCDHashFull sha256=5638e77cca038d7ad72621c52ca393356e030e43f6c83f137ca5a6fd306442c0"),
				test.AssertContains("CDHash=5638e77cca038d7ad72621c52ca393356e030e43"),
				test.AssertContains("CMSDigest=5638e77cca038d7ad72621c52ca393356e030e43f6c83f137ca5a6fd306442c0"),
				test.AssertContains("CMSDigestType=2"),
				test.AssertContains("Signature size="), // assert not adhoc
				test.AssertContains("Authority=quill-test-hello"),
				test.AssertContains("Info.plist=not bound"),
				test.AssertContains("TeamIdentifier=not set"),
				test.AssertContains("Sealed Resources=none"),
				test.AssertContains("Internal requirements count=1 size=48"),
			},
		},
		{
			name: "sign the syft binary - cert chain",
			args: args{
				id:       "syft-id",
				path:     test.AssetCopy(t, "syft_unsigned"),
				keyFile:  test.Asset(t, "chain-leaf-key.pem"),
				certFile: test.Asset(t, "chain.pem"),
			},
			assertions: []test.OutputAssertion{
				test.AssertContains("CodeDirectory v=20500 size=208904 flags=0x10000(runtime) hashes=6523+2 location=embedded"),
				test.AssertContains("Hash type=sha256 size=32"),
				test.AssertContains("CandidateCDHash sha256=d7273a0be24e8badeae7de4b7979418e82862ca5"),
				test.AssertContains("CandidateCDHashFull sha256=d7273a0be24e8badeae7de4b7979418e82862ca5b9998d25927d33ba1b827fc6"),
				test.AssertContains("CDHash=d7273a0be24e8badeae7de4b7979418e82862ca5"),
				test.AssertContains("CMSDigest=d7273a0be24e8badeae7de4b7979418e82862ca5b9998d25927d33ba1b827fc6"),
				test.AssertContains("CMSDigestType=2"),
				test.AssertContains("Signature size="), // assert not adhoc
				test.AssertContains("Authority=quill-test-leaf"),
				test.AssertContains("Authority=quill-test-intermediate-ca"),
				test.AssertContains("Authority=quill-test-root-ca"),
				test.AssertContains("Info.plist=not bound"),
				test.AssertContains("TeamIdentifier=not set"),
				test.AssertContains("Sealed Resources=none"),
				test.AssertContains("Internal requirements count=1 size=48"),
			},
		},
		{
			name: "sign the syft binary (with a password)",
			args: args{
				id:                        "syft-id",
				path:                      test.AssetCopy(t, "syft_unsigned"),
				keyFile:                   test.Asset(t, "x509-key.pem"),
				certFile:                  test.Asset(t, "x509-cert.pem"),
				keyPassword:               "5w0rdf15h",
				skipAssertAgainstCodesign: true, // this test fixture isn't configured to be trusted (you'll get a cssmerr_tp_not_trusted)
			},
			assertions: []test.OutputAssertion{
				test.AssertContains("CodeDirectory v=20500 size=208904 flags=0x10000(runtime) hashes=6523+2 location=embedded"),
				test.AssertContains("Hash type=sha256 size=32"),
				test.AssertContains("CandidateCDHash sha256=a1c1c60573a81e780c5cd11d3b17b252291a5739"),
				test.AssertContains("CandidateCDHashFull sha256=a1c1c60573a81e780c5cd11d3b17b252291a573915fa47e8927a00b1a877af1c"),
				test.AssertContains("CDHash=a1c1c60573a81e780c5cd11d3b17b252291a5739"),
				test.AssertContains("CMSDigest=a1c1c60573a81e780c5cd11d3b17b252291a573915fa47e8927a00b1a877af1c"),
				test.AssertContains("CMSDigestType=2"),
				test.AssertContains("Signature size="),         // assert not adhoc
				test.AssertContains("Authority=(unavailable)"), // since the cert is not trusted by the system
				test.AssertContains("Info.plist=not bound"),
				test.AssertContains("TeamIdentifier=not set"),
				test.AssertContains("Sealed Resources=none"),
				test.AssertContains("Internal requirements count=1 size=48"),
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg, err := NewSigningConfigFromPEMs(tt.args.path, tt.args.certFile, tt.args.keyFile, tt.args.keyPassword)
			require.NoError(t, err)
			cfg.WithIdentity(tt.args.id)
			// note: can't do this in snapshot testing
			//cfg.WithTimestampServer("http://timestamp.apple.com/ts01")

			require.NoError(t, Sign(cfg))
			test.AssertDebugOutput(t, tt.args.path, tt.assertions...)
			if !tt.args.skipAssertAgainstCodesign {
				test.AssertAgainstCodesignTool(t, tt.args.path)
			}
		})
	}
}
