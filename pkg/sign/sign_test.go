package sign

import (
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
				test.AssertContains("CodeDirectory v=20400 size=513 flags=0x20002(adhoc,linker-signed) hashes=13+0 location=embedded"),
				test.AssertContains("Hash type=sha256 size=32"),
				test.AssertContains("CandidateCDHash sha256=1ef4506947e8a5a2388e91bf2b319fa45746cc82"),
				test.AssertContains("CandidateCDHashFull sha256=1ef4506947e8a5a2388e91bf2b319fa45746cc82f98e49838dd63db9155d6fca"),
				test.AssertContains("CMSDigest=1ef4506947e8a5a2388e91bf2b319fa45746cc82f98e49838dd63db9155d6fca"),
				test.AssertContains("CMSDigestType=2"),
				test.AssertContains("Signature=adhoc"),
				test.AssertContains("Info.plist=not bound"),
				test.AssertContains("TeamIdentifier=not set"),
				test.AssertContains("Sealed Resources=none"),
				test.AssertContains("Internal requirements=none"),
			},
		},
		{
			name: "ad-hoc sign the syft binary (with a password)",
			args: args{
				id:   "syft-id",
				path: test.AssetCopy(t, "syft_unsigned"),
			},
			assertions: []test.OutputAssertion{
				test.AssertContains("CodeDirectory v=20400 size=208832 flags=0x20002(adhoc,linker-signed) hashes=6523+0 location=embedded"),
				test.AssertContains("Hash type=sha256 size=32"),
				test.AssertContains("CandidateCDHash sha256=a2c8eb9a76e4af5eea609d4db9f723ff01896ee8"),
				test.AssertContains("CandidateCDHashFull sha256=a2c8eb9a76e4af5eea609d4db9f723ff01896ee89bcfd23a760e7a966ac9d110"),
				test.AssertContains("CMSDigest=a2c8eb9a76e4af5eea609d4db9f723ff01896ee89bcfd23a760e7a966ac9d110"),
				test.AssertContains("CMSDigestType=2"),
				test.AssertContains("Signature=adhoc"),
				test.AssertContains("Info.plist=not bound"),
				test.AssertContains("TeamIdentifier=not set"),
				test.AssertContains("Sealed Resources=none"),
				test.AssertContains("Internal requirements=none"),
			},
		},
		// until CMS block is fixed the following tests will fail:
		{
			name: "sign the hello binary",
			args: args{
				id:       "my-id",
				path:     test.AssetCopy(t, "hello"),
				keyFile:  test.Asset(t, "hello-key.pem"),
				certFile: test.Asset(t, "hello-cert.pem"),
			},
			//assertions: []test.OutputAssertion{
			//	test.AssertContains("CodeDirectory v=20400 size=510 flags=0x10000(runtime) hashes=13+0 location=embedded"),
			//	test.AssertContains("Hash type=sha256 size=32"),
			//	test.AssertContains("CandidateCDHash sha256=6e291fbdc2c3a1a1e628dca4337c87a43390582e"),
			//	test.AssertContains("CandidateCDHashFull sha256=6e291fbdc2c3a1a1e628dca4337c87a43390582e4fa288f14e907ced58d53e35"),
			//	test.AssertContains("CMSDigest=6e291fbdc2c3a1a1e628dca4337c87a43390582e4fa288f14e907ced58d53e35"),
			//	test.AssertContains("CMSDigestType=2"),
			//	test.AssertContains("Signature=adhoc"),
			//	test.AssertContains("Info.plist=not bound"),
			//	test.AssertContains("TeamIdentifier=not set"),
			//	test.AssertContains("Sealed Resources=none"),
			//	test.AssertContains("Internal requirements=none"),
			//},
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
			//assertions: []test.OutputAssertion{
			//	test.AssertContains("CodeDirectory v=20400 size=208832 flags=0x10000(runtime) hashes=6523+0 location=embedded"),
			//	test.AssertContains("Hash type=sha256 size=32"),
			//	test.AssertContains("CandidateCDHash sha256=a2c8eb9a76e4af5eea609d4db9f723ff01896ee8"),
			//	test.AssertContains("CandidateCDHashFull sha256=a2c8eb9a76e4af5eea609d4db9f723ff01896ee89bcfd23a760e7a966ac9d110"),
			//	test.AssertContains("CMSDigest=a2c8eb9a76e4af5eea609d4db9f723ff01896ee89bcfd23a760e7a966ac9d110"),
			//	test.AssertContains("CMSDigestType=2"),
			//	test.AssertContains("Signature=adhoc"),
			//	test.AssertContains("Info.plist=not bound"),
			//	test.AssertContains("TeamIdentifier=not set"),
			//	test.AssertContains("Sealed Resources=none"),
			//	test.AssertContains("Internal requirements=none"),
			//},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.NoError(t, Sign(tt.args.id, tt.args.path, tt.args.keyFile, tt.args.keyPassword, tt.args.certFile))
			test.AssertDebugOutput(t, tt.args.path, tt.assertions...)
			test.AssertBinarySigned(t, tt.args.path)
		})
	}
}
