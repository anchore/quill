package bundle

import (
	"fmt"
	"os"
	"path/filepath"

	"howett.net/plist"
)

// Kind is the layout of a bundle. macOS uses two, and they differ in where the Info.plist,
// the main executable, and the code signature live:
//
//	KindApp        Foo.app / Foo.appex / Foo.xpc
//	               Contents/Info.plist -> Contents/MacOS/<CFBundleExecutable>
//	KindFramework  Foo.framework
//	               Versions/<v>/Resources/Info.plist -> Versions/<v>/<CFBundleExecutable>
//
// Frameworks are versioned and flat rather than having a Contents directory, so treating one
// as the other reports a valid framework as having no main executable.
type Kind int

const (
	// KindApp is a bundle with a Contents directory (an app, app extension, or XPC service)
	KindApp Kind = iota

	// KindFramework is a versioned framework bundle
	KindFramework
)

func (k Kind) String() string {
	switch k {
	case KindApp:
		return "application"
	case KindFramework:
		return "framework"
	}
	return "unknown"
}

// frameworkVersions are the version directories searched for a framework's current version,
// in preference order. "Current" is conventionally a symlink to the real version.
var frameworkVersions = []string{"Current", "A"}

// Bundle represents a macOS bundle: a directory with an Info.plist describing the main
// executable within it. Both layouts named by Kind are supported.
type Bundle struct {
	// Root is the path to the bundle directory (e.g. "/path/to/My.app")
	Root string

	// Kind is the layout of the bundle
	Kind Kind

	// Info contains fields parsed from the bundle's Info.plist
	Info Info

	// contentsDir is the directory holding the bundle's content, relative to Root:
	// "Contents" for an app bundle, "Versions/<v>" for a framework
	contentsDir string

	infoPlistData []byte
}

// Info is the set of Info.plist fields needed for signing.
type Info struct {
	// Identifier is the CFBundleIdentifier value, used as the signing identity of the main executable
	Identifier string `plist:"CFBundleIdentifier"`

	// Executable is the CFBundleExecutable value, the name of the main executable
	Executable string `plist:"CFBundleExecutable"`
}

// IsBundle indicates if the given path appears to be a bundle of any kind. It only looks for
// a bundle layout; use New to parse one and to find out why a bundle is unusable.
func IsBundle(path string) bool {
	if fi, err := os.Stat(path); err != nil || !fi.IsDir() {
		return false
	}
	_, _, found := findInfoPlist(path)
	return found
}

// New parses the bundle at the given root directory, validating that an Info.plist and a main
// executable exist. Both bundle layouts are supported; the result reports which one via Kind.
func New(root string) (*Bundle, error) {
	kind, contentsDir, found := findInfoPlist(root)
	if !found {
		return nil, fmt.Errorf("not a bundle (no Contents/Info.plist and no framework layout): %s", root)
	}

	infoPath := filepath.Join(root, contentsDir, infoPlistRelPath(kind))
	data, err := os.ReadFile(infoPath)
	if err != nil {
		return nil, fmt.Errorf("unable to read %s Info.plist %s: %w", kind, infoPath, err)
	}

	var info Info
	if _, err := plist.Unmarshal(data, &info); err != nil {
		return nil, fmt.Errorf("unable to parse %s Info.plist %s: %w", kind, infoPath, err)
	}

	if info.Executable == "" {
		return nil, fmt.Errorf("%s Info.plist has no CFBundleExecutable entry: %s", kind, infoPath)
	}

	b := &Bundle{
		Root:          root,
		Kind:          kind,
		Info:          info,
		contentsDir:   contentsDir,
		infoPlistData: data,
	}

	if fi, err := os.Stat(b.MainExecutablePath()); err != nil || !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("%s main executable named by Info.plist not found: %s", kind, b.MainExecutablePath())
	}

	return b, nil
}

// findInfoPlist locates the bundle layout at the given root, returning its kind and the
// content directory relative to the root (e.g. "Contents" or "Versions/A").
func findInfoPlist(root string) (kind Kind, contentsDir string, found bool) {
	if isRegularFile(filepath.Join(root, "Contents", infoPlistRelPath(KindApp))) {
		return KindApp, "Contents", true
	}

	for _, version := range frameworkVersions {
		dir := filepath.Join("Versions", version)
		if isRegularFile(filepath.Join(root, dir, infoPlistRelPath(KindFramework))) {
			return KindFramework, dir, true
		}
	}

	return KindApp, "", false
}

// infoPlistRelPath returns the path of the Info.plist within a bundle's content directory.
func infoPlistRelPath(kind Kind) string {
	if kind == KindFramework {
		return filepath.Join("Resources", "Info.plist")
	}
	return "Info.plist"
}

func isRegularFile(path string) bool {
	fi, err := os.Stat(path)
	return err == nil && fi.Mode().IsRegular()
}

// InfoPlistData returns the raw bytes of the bundle's Info.plist.
func (b Bundle) InfoPlistData() []byte {
	return b.infoPlistData
}

// MainExecutablePath returns the path to the bundle's main executable.
func (b Bundle) MainExecutablePath() string {
	if b.Kind == KindFramework {
		// frameworks are flat: the executable sits directly in the version directory
		return filepath.Join(b.Root, b.contentsDir, b.Info.Executable)
	}
	return filepath.Join(b.Root, b.contentsDir, "MacOS", b.Info.Executable)
}

// CodeResourcesPath returns the path where the bundle's resource seal is written.
func (b Bundle) CodeResourcesPath() string {
	return filepath.Join(b.Root, b.contentsDir, "_CodeSignature", "CodeResources")
}
