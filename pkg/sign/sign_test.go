package sign

import (
	"github.com/anchore/quill/pkg/pem"
	"testing"

	"github.com/anchore/quill/internal/test"
	"github.com/stretchr/testify/require"
)

func TestSign(t *testing.T) {

	type args struct {
		id          string
		path        string
		keyFile     string
		keyPassword string
		certFile    string
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
			name: "ad-hoc sign the syft binary (with a password)",
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
			name: "sign the hello binary",
			args: args{
				id:       "my-id",
				path:     test.AssetCopy(t, "hello"),
				keyFile:  test.Asset(t, "hello-key.pem"),
				certFile: test.Asset(t, "hello-cert.pem"),
			},
			assertions: []test.OutputAssertion{
				test.AssertContains("CodeDirectory v=20500 size=582 flags=0x10000(runtime) hashes=13+2 location=embedded"),
				test.AssertContains("Hash type=sha256 size=32"),
				test.AssertContains("CandidateCDHash sha256=e94e41499a43d1fc823d36983a635264239c8c31"),
				test.AssertContains("CandidateCDHashFull sha256=e94e41499a43d1fc823d36983a635264239c8c31412f19f4e8787eb5a83b29da"),
				test.AssertContains("CDHash=e94e41499a43d1fc823d36983a635264239c8c31"),
				test.AssertContains("CMSDigest=e94e41499a43d1fc823d36983a635264239c8c31412f19f4e8787eb5a83b29da"),
				test.AssertContains("CMSDigestType=2"),
				test.AssertContains("Signature size="), // assert not adhoc
				test.AssertContains("Authority=quill-test-hello"),
				test.AssertContains("Info.plist=not bound"),
				test.AssertContains("TeamIdentifier=not set"),
				test.AssertContains("Sealed Resources=none"),
				test.AssertContains("Internal requirements count=0 size=12"),
			},
		},
		{
			name: "sign the syft binary (with a password)",
			args: args{
				id:          "syft-id",
				path:        test.AssetCopy(t, "syft_unsigned"),
				keyFile:     test.Asset(t, "x509-key.pem"),
				certFile:    test.Asset(t, "x509-cert.pem"),
				keyPassword: "5w0rdf15h",
			},
			assertions: []test.OutputAssertion{
				test.AssertContains("CodeDirectory v=20500 size=208904 flags=0x10000(runtime) hashes=6523+2 location=embedded"),
				test.AssertContains("Hash type=sha256 size=32"),
				test.AssertContains("CandidateCDHash sha256=6de57d1afedd91276e44f95814374f2f991aa504"),
				test.AssertContains("CandidateCDHashFull sha256=6de57d1afedd91276e44f95814374f2f991aa50469e3ec7c93ac456967091545"),
				test.AssertContains("CDHash=6de57d1afedd91276e44f95814374f2f991aa504"),
				test.AssertContains("CMSDigest=6de57d1afedd91276e44f95814374f2f991aa50469e3ec7c93ac456967091545"),
				test.AssertContains("CMSDigestType=2"),
				test.AssertContains("Signature size="), // assert not adhoc
				test.AssertContains("Authority=quill-test-hello"),
				test.AssertContains("Info.plist=not bound"),
				test.AssertContains("TeamIdentifier=not set"),
				test.AssertContains("Sealed Resources=none"),
				test.AssertContains("Internal requirements count=0 size=12"),
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			signingMaterial, err := pem.NewSigningMaterial(tt.args.certFile, tt.args.keyFile, tt.args.keyPassword)
			require.NoError(t, err)
			require.NoError(t, Sign(tt.args.id, tt.args.path, signingMaterial))
			test.AssertDebugOutput(t, tt.args.path, tt.assertions...)
			test.AssertBinarySigned(t, tt.args.path)
		})
	}
}
