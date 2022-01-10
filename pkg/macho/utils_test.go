package macho

import (
	"bufio"
	"io"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/gookit/color"
)

// generateMakeFixture will run the default make target for the given test fixture path
func generateMakeFixture(t *testing.T, fixtureName string) {
	cwd, err := os.Getwd()
	if err != nil {
		t.Errorf("unable to get cwd: %+v", err)
	}
	path := filepath.Join(cwd, "test-fixtures/", fixtureName)

	t.Logf(color.Bold.Sprintf("Generating Fixture in %q", path))

	cmd := exec.Command("make")
	cmd.Dir = path

	stderr, err := cmd.StderrPipe()
	if err != nil {
		t.Fatalf("could not get stderr: %+v", err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatalf("could not get stdout: %+v", err)
	}

	err = cmd.Start()
	if err != nil {
		t.Fatalf("failed to start cmd: %+v", err)
	}

	show := func(label string, reader io.ReadCloser) {
		scanner := bufio.NewScanner(reader)
		scanner.Split(bufio.ScanLines)
		for scanner.Scan() {
			t.Logf("%s: %s", label, scanner.Text())
		}
	}
	go show("out", stdout)
	go show("err", stderr)

	if err := cmd.Wait(); err != nil {
		if exiterr, ok := err.(*exec.ExitError); ok {
			// The program has exited with an exit code != 0

			// This works on both Unix and Windows. Although package
			// syscall is generally platform dependent, WaitStatus is
			// defined for both Unix and Windows and in both cases has
			// an ExitStatus() method with the same signature.
			if status, ok := exiterr.Sys().(syscall.WaitStatus); ok {
				if status.ExitStatus() != 0 {
					t.Fatalf("failed to generate fixture: rc=%d", status.ExitStatus())
				}
			}
		} else {
			t.Fatalf("unable to get generate fixture result: %+v", err)
		}
	}
}

// testAssetCopy will setup a new binary from copyFile of fixture for a test setup (+ autocleanup)
func testAssetCopy(t *testing.T, assetName string) string {
	assetPath := testAsset(t, assetName)
	dir := t.TempDir()
	destPath := filepath.Join(dir, assetName)
	copyFile(t, assetPath, destPath)
	return destPath
}

// testAsset returns the path to the cached asset file for a generated test fixture
func testAsset(t *testing.T, assetName string) string {
	assetPath := filepath.Join("test-fixtures", "assets", assetName)
	if _, err := os.Stat(assetPath); os.IsNotExist(err) {
		t.Fatalf("unable to find fixture %q", assetPath)
	}
	return assetPath
}

func copyFile(t *testing.T, src, dest string) {
	input, err := ioutil.ReadFile(src)
	if err != nil {
		t.Fatalf("unable to read source: %+v", err)
	}

	if err = ioutil.WriteFile(dest, input, 0644); err != nil {
		t.Fatalf("unable to write to destintion: %+v", err)

	}
}
