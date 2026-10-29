package main

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"

	. "github.com/anchore/go-make"
	"github.com/anchore/go-make/config"
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
		// the snapshot is only built when missing: in CI it is downloaded from the snapshot job, and rebuilding
		// would burn time and clobber it.
		Task{
			Name:        "cli",
			Description: "run CLI tests",
			RunsOn:      lang.List("test"),
			Run: func() {
				bin := findSnapshotBinary()
				if bin == "" {
					Log("no snapshot binary found, building a single-target snapshot")
					Run("make snapshot:single-target")
					bin = findSnapshotBinary()
					if bin == "" {
						lang.Throw(fmt.Errorf("no snapshot binary found matching %q after building one", snapshotBinaryGlob()))
					}
				}
				Log("testing binary: %s", bin)
				Run("go test -count=1 -timeout=15m ./test/cli/...", run.Env("QUILL_BINARY_LOCATION", bin), run.Stdout(os.Stderr))
			},
		},
		// the cli tests exec the snapshot binary, so -race there would only instrument the test harness. This runs
		// quill itself under the race detector once, offline, against a checked-in fixture.
		Task{
			Name:        "cli:race-smoke",
			Description: "exercise the cli with the race detector",
			RunsOn:      lang.List("cli"),
			Run: func() {
				if !raceEnabled() {
					Log("race detector disabled, skipping race smoke")
					return
				}
				Run("go run -race ./cmd/quill describe ./test/cli/test-fixtures/assets/hello_signed", run.Stdout(os.Stderr))
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

// findSnapshotBinary returns the absolute path to the snapshot quill binary for the current host, or "" when
// there isn't one. Goreleaser emits GOAMD64/GOARM64 variant suffixes (e.g. amd64_v1, arm64_v8.0) on the dist
// dir name, and those defaults shift across goreleaser versions, so glob rather than hardcode.
func findSnapshotBinary() string {
	matches := lang.Return(filepath.Glob(snapshotBinaryGlob()))
	if len(matches) == 0 {
		return ""
	}
	return matches[0]
}

func snapshotBinaryGlob() string {
	return filepath.Join(RootDir(), "snapshot", fmt.Sprintf("%s-build_%s_%s*", runtime.GOOS, runtime.GOOS, runtime.GOARCH), "quill")
}

// raceEnabled defaults to on in CI (off on windows) and can be forced either way with RACE=true|false.
func raceEnabled() bool {
	if enabled, err := strconv.ParseBool(config.Env("RACE", "")); err == nil {
		return enabled
	}
	return config.CI && !config.Windows
}
