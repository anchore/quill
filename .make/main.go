package main

import (
	"fmt"
	"path/filepath"
	"runtime"

	. "github.com/anchore/go-make"
	"github.com/anchore/go-make/lang"
	"github.com/anchore/go-make/run"
	"github.com/anchore/go-make/tasks/golint"
	"github.com/anchore/go-make/tasks/goreleaser"
	"github.com/anchore/go-make/tasks/gotest"
)

func main() {
	Makefile(
		golint.Tasks(),
		goreleaser.Tasks(),
		gotest.Tasks(
			// the test/cli and test/trait packages drive the built snapshot binary, so they
			// aren't unit tests — they have a dedicated `cli` task that depends on `snapshot`.
			gotest.ExcludeGlob("**/test/**"),
			gotest.CoverageThreshold(40),
		),

		// quill-specific tasks not covered by go-make built-ins

		Task{
			Name:        "fingerprints",
			Description: "create all test cache input fingerprints",
			Run: func() {
				Run("make cache.fingerprint", run.InDir("test/install"))
			},
		},
		Task{
			Name:        "install-test",
			Description: "run install.sh tests",
			Run: func() {
				Run("make", run.InDir("test/install"))
			},
		},
		Task{
			Name:        "install-test-cache-save",
			Description: "save install test cache",
			Run: func() {
				Run("make save", run.InDir("test/install"))
			},
		},
		Task{
			Name:        "install-test-cache-load",
			Description: "load install test cache",
			Run: func() {
				Run("make load", run.InDir("test/install"))
			},
		},
		Task{
			Name:        "cli",
			Description: "run CLI tests",
			Run: func() {
				bin := findSnapshotBinary()
				Run("chmod 755 " + bin)
				Run(bin + " version")
				// QUILL_BINARY_LOCATION lets test/cli skip its own GOOS/GOARCH path resolution, which
				// doesn't handle goreleaser's GOARM64 variant suffix (e.g. arm64_v8.0) on the dist dir.
				Run("go test -count=1 -timeout=15m -v ./test/cli", run.Env("QUILL_BINARY_LOCATION", bin))
			},
		},
		Task{
			Name:        "update-apple-certs",
			Description: "update the apple certs checked into the repo",
			Run: func() {
				Run("go generate ./quill/pki/apple")
			},
		},
	)
}

// findSnapshotBinary resolves the snapshot quill binary for the current host as an absolute
// path (test/cli changes cwd, so relative paths break). Goreleaser emits GOAMD64/GOARM64
// variant suffixes (e.g. amd64_v1, arm64_v8.0) on the dist dir name, and those defaults shift
// across goreleaser versions, so glob rather than hardcode.
func findSnapshotBinary() string {
	pattern := fmt.Sprintf("./snapshot/%s-build_%s_%s*/quill", runtime.GOOS, runtime.GOOS, runtime.GOARCH)
	matches := lang.Return(filepath.Glob(pattern))
	if len(matches) == 0 {
		lang.Throw(fmt.Errorf("no snapshot binary found matching %q — did you run `make snapshot`?", pattern))
	}
	return lang.Return(filepath.Abs(matches[0]))
}
