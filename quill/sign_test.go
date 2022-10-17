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
		{
			name: "ad-hoc sign syft arm64 binary",
			args: args{
				id:   "syft",
				path: test.AssetCopy(t, "syft_unsigned_arm64"),
			},
			assertions: []test.OutputAssertion{
				test.AssertContains("CodeDirectory v=20500 size=650917 flags=0x2(adhoc) hashes=20336+2 location=embedded"),
				test.AssertContains("Hash type=sha256 size=32"),
				test.AssertContains("CandidateCDHash sha256=ce9492daee16069dc188617132146738114576fc"),
				test.AssertContains("CandidateCDHashFull sha256=ce9492daee16069dc188617132146738114576fc7737f57c977b0d2fe737f9cf"),
				test.AssertContains("CDHash=ce9492daee16069dc188617132146738114576fc"),
				test.AssertContains("CMSDigest=ce9492daee16069dc188617132146738114576fc7737f57c977b0d2fe737f9cf"),
				test.AssertContains("CMSDigestType=2"),
				test.AssertContains("Signature=adhoc"),
				test.AssertContains("Info.plist=not bound"),
				test.AssertContains("TeamIdentifier=not set"),
				test.AssertContains("Sealed Resources=none"),
				test.AssertContains("Internal requirements count=0 size=12"),
			},
		},
		{
			name: "ad-hoc sign the hello binary",
			args: args{
				id:   "hello-id",
				path: test.AssetCopy(t, "hello"),
			},
			assertions: []test.OutputAssertion{
				test.AssertContains("CodeDirectory v=20500 size=585 flags=0x2(adhoc) hashes=13+2 location=embedded"),
				test.AssertContains("Hash type=sha256 size=32"),
				test.AssertContains("CandidateCDHash sha256=75be1f393e6650da91bf4e78e1d5bb09c90b671f"),
				test.AssertContains("CandidateCDHashFull sha256=75be1f393e6650da91bf4e78e1d5bb09c90b671f52865a2149c239040364fd66"),
				test.AssertContains("CDHash=75be1f393e6650da91bf4e78e1d5bb09c90b671f"),
				test.AssertContains("CMSDigest=75be1f393e6650da91bf4e78e1d5bb09c90b671f52865a2149c239040364fd66"),
				test.AssertContains("CMSDigestType=2"),
				test.AssertContains("Signature=adhoc"),
				test.AssertContains("Info.plist=not bound"),
				test.AssertContains("TeamIdentifier=not set"),
				test.AssertContains("Sealed Resources=none"),
				test.AssertContains("Internal requirements count=0 size=12"),
			},
		},
		{
			name: "ad-hoc sign the syft binary",
			args: args{
				id:   "syft-id",
				path: test.AssetCopy(t, "syft_unsigned"),
			},
			assertions: []test.OutputAssertion{
				test.AssertContains("CodeDirectory v=20500 size=208904 flags=0x2(adhoc) hashes=6523+2 location=embedded"),
				test.AssertContains("Hash type=sha256 size=32"),
				test.AssertContains("CandidateCDHash sha256=ba0302d64e12b56a26b88e42b008fffa078c7360"),
				test.AssertContains("CandidateCDHashFull sha256=ba0302d64e12b56a26b88e42b008fffa078c7360ecbda378626815263b6a9d8f"),
				test.AssertContains("CDHash=ba0302d64e12b56a26b88e42b008fffa078c7360"),
				test.AssertContains("CMSDigest=ba0302d64e12b56a26b88e42b008fffa078c7360ecbda378626815263b6a9d8f"),
				test.AssertContains("CMSDigestType=2"),
				test.AssertContains("Signature=adhoc"),
				test.AssertContains("Info.plist=not bound"),
				test.AssertContains("TeamIdentifier=not set"),
				test.AssertContains("Sealed Resources=none"),
				test.AssertContains("Internal requirements count=0 size=12"),
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
		{
			// note: this test will fail with other architectures (e.g. arm64) since the output assertions are for x86_64
			// but codesign will dynamically select the architecture based on the current host architecture
			name: "sign multi arch binary - cert chain",
			args: args{
				id:       "ls",
				path:     test.AssetCopy(t, "ls_universal_signed"),
				keyFile:  test.Asset(t, "chain-leaf-key.pem"),
				certFile: test.Asset(t, "chain.pem"),
			},
			assertions: []test.OutputAssertion{
				test.AssertContains("CodeDirectory v=20500 size=643 flags=0x10000(runtime) hashes=15+2 location=embedded"),
				test.AssertContains("Hash type=sha256 size=32"),
				test.AssertContains("CandidateCDHash sha256=a4cd4a5f49f232086ba698ec3bba3f086f432dea"),
				test.AssertContains("CandidateCDHashFull sha256=a4cd4a5f49f232086ba698ec3bba3f086f432deae7d6ba648895e935b5098307"),
				test.AssertContains("CDHash=a4cd4a5f49f232086ba698ec3bba3f086f432dea"),
				test.AssertContains("CMSDigest=a4cd4a5f49f232086ba698ec3bba3f086f432deae7d6ba648895e935b5098307"),
				test.AssertContains("CMSDigestType=2"),
				test.AssertContains("Signature size="), // assert not adhoc
				test.AssertContains("Authority=quill-test-leaf"),
				test.AssertContains("Authority=quill-test-intermediate-ca"),
				test.AssertContains("Authority=quill-test-root-ca"),
				test.AssertContains("Info.plist=not bound"),
				test.AssertContains("TeamIdentifier=not set"),
				test.AssertContains("Sealed Resources=none"),
				test.AssertContains("Internal requirements count=1 size=44"),
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

			require.NoError(t, Sign(*cfg))
			test.AssertDebugOutput(t, tt.args.path, tt.assertions...)
			if !tt.args.skipAssertAgainstCodesign {
				test.AssertAgainstCodesignTool(t, tt.args.path)
			}
		})
	}
}
