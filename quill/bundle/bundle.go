package bundle

import (
	"fmt"
	"os"
	"path/filepath"

	"howett.net/plist"
)

// Bundle represents a macOS application bundle: a directory with a
// Contents/Info.plist describing the main executable within Contents/MacOS.
type Bundle struct {
	// Root is the path to the bundle directory (e.g. "/path/to/My.app")
	Root string

	// Info contains fields parsed from Contents/Info.plist
	Info Info

	infoPlistData []byte
}

// Info is the set of Info.plist fields needed for signing.
type Info struct {
	// Identifier is the CFBundleIdentifier value, used as the signing identity of the main executable
	Identifier string `plist:"CFBundleIdentifier"`

	// Executable is the CFBundleExecutable value, the name of the main executable within Contents/MacOS
	Executable string `plist:"CFBundleExecutable"`
}

// MainExecutableOf returns the path of the main executable of the bundle rooted at the
// given directory, handling both bundle layouts macOS uses.
//
//	Foo.app / Foo.appex / Foo.xpc   Contents/Info.plist -> Contents/MacOS/<CFBundleExecutable>
//	Foo.framework                   Versions/<v>/Resources/Info.plist -> Versions/<v>/<CFBundleExecutable>
//
// Frameworks are versioned and flat rather than having a Contents directory, so the
// shallow layout has to be handled explicitly; treating one as the other yields a
// "main executable not found" error on a perfectly valid bundle.
func MainExecutableOf(root string) (string, error) {
	if IsBundle(root) {
		b, err := New(root)
		if err != nil {
			return "", err
		}
		return b.MainExecutablePath(), nil
	}

	if exe, err := frameworkMainExecutable(root); err == nil {
		return exe, nil
	}

	return "", fmt.Errorf("not a bundle (no Contents/Info.plist and no framework layout): %s", root)
}

// frameworkMainExecutable resolves the main executable of a versioned framework bundle.
func frameworkMainExecutable(root string) (string, error) {
	for _, version := range []string{"Current", "A"} {
		versionDir := filepath.Join(root, "Versions", version)
		infoPath := filepath.Join(versionDir, "Resources", "Info.plist")

		data, err := os.ReadFile(infoPath)
		if err != nil {
			continue
		}
		var info Info
		if _, err := plist.Unmarshal(data, &info); err != nil {
			return "", fmt.Errorf("unable to parse framework Info.plist %s: %w", infoPath, err)
		}
		if info.Executable == "" {
			return "", fmt.Errorf("framework Info.plist has no CFBundleExecutable entry: %s", infoPath)
		}

		exe := filepath.Join(versionDir, info.Executable)
		if fi, err := os.Stat(exe); err == nil && fi.Mode().IsRegular() {
			return exe, nil
		}
	}
	return "", fmt.Errorf("no framework main executable found under %s", root)
}

// IsBundle indicates if the given path appears to be an application bundle (a directory containing Contents/Info.plist).
func IsBundle(path string) bool {
	fi, err := os.Stat(path)
	if err != nil || !fi.IsDir() {
		return false
	}
	fi, err = os.Stat(filepath.Join(path, "Contents", "Info.plist"))
	return err == nil && fi.Mode().IsRegular()
}

// New parses the bundle at the given root directory, validating that an Info.plist and main executable exist.
func New(root string) (*Bundle, error) {
	infoPath := filepath.Join(root, "Contents", "Info.plist")
	data, err := os.ReadFile(infoPath)
	if err != nil {
		return nil, fmt.Errorf("unable to read bundle Info.plist: %w", err)
	}

	var info Info
	if _, err := plist.Unmarshal(data, &info); err != nil {
		return nil, fmt.Errorf("unable to parse bundle Info.plist: %w", err)
	}

	if info.Executable == "" {
		return nil, fmt.Errorf("bundle Info.plist has no CFBundleExecutable entry: %s", infoPath)
	}

	b := &Bundle{
		Root:          root,
		Info:          info,
		infoPlistData: data,
	}

	if fi, err := os.Stat(b.MainExecutablePath()); err != nil || !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("bundle main executable not found: %s", b.MainExecutablePath())
	}

	return b, nil
}

// InfoPlistData returns the raw bytes of Contents/Info.plist.
func (b Bundle) InfoPlistData() []byte {
	return b.infoPlistData
}

// MainExecutablePath returns the path to the main executable (Contents/MacOS/<CFBundleExecutable>).
func (b Bundle) MainExecutablePath() string {
	return filepath.Join(b.Root, "Contents", "MacOS", b.Info.Executable)
}

// CodeResourcesPath returns the path where the resources seal is written (Contents/_CodeSignature/CodeResources).
func (b Bundle) CodeResourcesPath() string {
	return filepath.Join(b.Root, "Contents", "_CodeSignature", "CodeResources")
}
