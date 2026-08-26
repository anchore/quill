package bundle

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"howett.net/plist"
)

// fakeSealer records an already-signed nested bundle without touching Mach-O parsing, so
// the sealing logic can be tested independently of real signed binaries.
type fakeSealer struct {
	sealed []string
	info   *SignedBinaryInfo
	err    error
}

func (f *fakeSealer) SignMachO(string) (*SignedBinaryInfo, error) {
	return &SignedBinaryInfo{CDHash: []byte("0123456789abcdefghij")}, nil
}

func (f *fakeSealer) SealNestedBundle(p string) (*SignedBinaryInfo, error) {
	f.sealed = append(f.sealed, p)
	if f.err != nil {
		return nil, f.err
	}
	return f.info, nil
}

// plainSigner implements only MachOSigner, so it must keep the previous behavior.
type plainSigner struct{}

func (plainSigner) SignMachO(string) (*SignedBinaryInfo, error) {
	return &SignedBinaryInfo{CDHash: []byte("0123456789abcdefghij")}, nil
}

// appWithNestedAppex builds the bundle layout that a File Provider extension requires:
// an .app whose Contents/PlugIns holds a .appex.
func appWithNestedAppex(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	app := filepath.Join(root, "SFTP.app")

	mustMkdir(t, filepath.Join(app, "Contents", "MacOS"))
	mustMkdir(t, filepath.Join(app, "Contents", "Resources"))
	mustWrite(t, filepath.Join(app, "Contents", "MacOS", "SFTP"), "main executable")
	mustWrite(t, filepath.Join(app, "Contents", "Resources", "asset.txt"), "a resource")
	mustWrite(t, filepath.Join(app, "Contents", "Info.plist"), infoPlist("SFTP", "com.example.SFTP"))

	appex := filepath.Join(app, "Contents", "PlugIns", "SFTPFileProvider.appex")
	mustMkdir(t, filepath.Join(appex, "Contents", "MacOS"))
	mustWrite(t, filepath.Join(appex, "Contents", "MacOS", "SFTPFileProvider"), "extension executable")
	mustWrite(t, filepath.Join(appex, "Contents", "Info.plist"),
		infoPlist("SFTPFileProvider", "com.example.SFTP.FileProvider"))
	// The nested bundle's own seal, which the parent must not descend into.
	mustMkdir(t, filepath.Join(appex, "Contents", "_CodeSignature"))
	mustWrite(t, filepath.Join(appex, "Contents", "_CodeSignature", "CodeResources"), "nested seal")

	return app
}

func mustMkdir(t *testing.T, p string) {
	t.Helper()
	if err := os.MkdirAll(p, 0o755); err != nil {
		t.Fatal(err)
	}
}

func mustWrite(t *testing.T, p, content string) {
	t.Helper()
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func infoPlist(executable, identifier string) string {
	return `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>CFBundleExecutable</key><string>` + executable + `</string>
<key>CFBundleIdentifier</key><string>` + identifier + `</string>
</dict></plist>`
}

func sealApp(t *testing.T, app string, signer MachOSigner) (map[string]any, error) {
	t.Helper()
	b := NewResourcesBuilder()
	if err := b.ExcludePath("MacOS/SFTP"); err != nil {
		t.Fatal(err)
	}
	if err := b.WalkAndSeal(app, signer); err != nil {
		return nil, err
	}
	data, err := b.Assemble()
	if err != nil {
		t.Fatal(err)
	}
	var out map[string]any
	if _, err := plist.Unmarshal(data, &out); err != nil {
		t.Fatal(err)
	}
	return out, nil
}

func TestNestedBundleIsSealedByReference(t *testing.T) {
	app := appWithNestedAppex(t)
	sealer := &fakeSealer{info: &SignedBinaryInfo{
		CDHash:      []byte("0123456789abcdefghij"),
		Requirement: `identifier "com.example.SFTP.FileProvider" and anchor apple generic`,
	}}

	out, err := sealApp(t, app, sealer)
	if err != nil {
		t.Fatalf("sealing an app with a nested appex failed: %v", err)
	}

	files2 := out["files2"].(map[string]any)
	const key = "PlugIns/SFTPFileProvider.appex"

	entry, ok := files2[key].(map[string]any)
	if !ok {
		t.Fatalf("the nested bundle was not sealed; files2 holds %v", keysOf(files2))
	}
	if _, ok := entry["cdhash"]; !ok {
		t.Error("the nested bundle entry has no cdhash")
	}
	if got, _ := entry["requirement"].(string); !strings.Contains(got, "com.example.SFTP.FileProvider") {
		t.Errorf("the nested bundle entry has no designated requirement, got %q", got)
	}
	// Apple seals nested bundles by content hash nowhere: the entry carries a reference
	// to the child's signature and nothing else.
	if _, ok := entry["hash2"]; ok {
		t.Error("a nested bundle must be sealed by reference, not by content hash")
	}
}

func TestNestedBundleContentsAreNotSealedByTheParent(t *testing.T) {
	// The child's own signature covers its contents. Repeating them in the parent both
	// duplicates work and diverges from what codesign emits.
	app := appWithNestedAppex(t)
	sealer := &fakeSealer{info: &SignedBinaryInfo{CDHash: []byte("0123456789abcdefghij")}}

	out, err := sealApp(t, app, sealer)
	if err != nil {
		t.Fatal(err)
	}
	files2 := out["files2"].(map[string]any)
	for k := range files2 {
		if strings.HasPrefix(k, "PlugIns/SFTPFileProvider.appex/") {
			t.Errorf("the parent sealed %q, which lives inside the nested bundle", k)
		}
	}
}

func TestNestedBundleIsAbsentFromVersion1Files(t *testing.T) {
	// The version 1 "files" section predates nested code; codesign records nested bundles
	// only in files2.
	app := appWithNestedAppex(t)
	sealer := &fakeSealer{info: &SignedBinaryInfo{CDHash: []byte("0123456789abcdefghij")}}

	out, err := sealApp(t, app, sealer)
	if err != nil {
		t.Fatal(err)
	}
	files := out["files"].(map[string]any)
	if _, ok := files["PlugIns/SFTPFileProvider.appex"]; ok {
		t.Error("the nested bundle appears in the version 1 files section")
	}
}

func TestOrdinaryResourcesAreStillSealed(t *testing.T) {
	app := appWithNestedAppex(t)
	sealer := &fakeSealer{info: &SignedBinaryInfo{CDHash: []byte("0123456789abcdefghij")}}

	out, err := sealApp(t, app, sealer)
	if err != nil {
		t.Fatal(err)
	}
	files2 := out["files2"].(map[string]any)
	if _, ok := files2["Resources/asset.txt"]; !ok {
		t.Errorf("an ordinary resource was not sealed; files2 holds %v", keysOf(files2))
	}
}

func TestSignerWithoutNestedSupportStillRefuses(t *testing.T) {
	// Existing callers must not silently start producing a seal that omits nested code.
	app := appWithNestedAppex(t)
	_, err := sealApp(t, app, plainSigner{})
	if err == nil {
		t.Fatal("a signer without nested-bundle support was allowed to seal a bundle containing one")
	}
	if !strings.Contains(err.Error(), "nested bundles is not supported") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestSealerErrorIsReportedWithContext(t *testing.T) {
	app := appWithNestedAppex(t)
	sealer := &fakeSealer{err: os.ErrNotExist}
	_, err := sealApp(t, app, sealer)
	if err == nil {
		t.Fatal("a sealing failure was swallowed")
	}
	if !strings.Contains(err.Error(), "SFTPFileProvider.appex") {
		t.Errorf("the error does not name the bundle that failed: %v", err)
	}
}

func TestMainExecutableOfAppBundle(t *testing.T) {
	app := appWithNestedAppex(t)
	got, err := MainExecutableOf(app)
	if err != nil {
		t.Fatal(err)
	}
	if filepath.Base(got) != "SFTP" {
		t.Errorf("MainExecutableOf = %q, want the SFTP executable", got)
	}
}

func TestMainExecutableOfAppExBundle(t *testing.T) {
	app := appWithNestedAppex(t)
	appex := filepath.Join(app, "Contents", "PlugIns", "SFTPFileProvider.appex")
	got, err := MainExecutableOf(appex)
	if err != nil {
		t.Fatal(err)
	}
	if filepath.Base(got) != "SFTPFileProvider" {
		t.Errorf("MainExecutableOf = %q, want the extension executable", got)
	}
}

func TestMainExecutableOfFramework(t *testing.T) {
	// Frameworks are versioned and flat rather than having a Contents directory; treating
	// one as an app bundle would report a valid framework as having no main executable.
	root := t.TempDir()
	fw := filepath.Join(root, "Widget.framework")
	mustMkdir(t, filepath.Join(fw, "Versions", "A", "Resources"))
	mustWrite(t, filepath.Join(fw, "Versions", "A", "Widget"), "framework binary")
	mustWrite(t, filepath.Join(fw, "Versions", "A", "Resources", "Info.plist"),
		infoPlist("Widget", "com.example.Widget"))

	got, err := MainExecutableOf(fw)
	if err != nil {
		t.Fatalf("MainExecutableOf on a framework: %v", err)
	}
	if filepath.Base(got) != "Widget" {
		t.Errorf("MainExecutableOf = %q, want the framework binary", got)
	}
}

func TestMainExecutableOfNonBundle(t *testing.T) {
	if _, err := MainExecutableOf(t.TempDir()); err == nil {
		t.Error("a plain directory was accepted as a bundle")
	}
}

func keysOf(m map[string]any) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
