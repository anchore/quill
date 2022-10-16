package cli

import (
	"bytes"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/gookit/color"

	"github.com/anchore/quill/test/trait"
)

const defaultShowOutput = false

var showStdout = flag.Bool("stdout", defaultShowOutput, "Show command stdout")
var showStderr = flag.Bool("stderr", defaultShowOutput, "Show command stderr")
var detail = flag.Bool("detail", defaultShowOutput, "Show test detail output")

type runConfig struct {
	commentary string
	env        map[string]string
	timeout    time.Duration
	stdin      io.Reader
}

func runQuill(t testing.TB, command string, cfgs ...runConfig) (string, string, error) {
	var stdout, stderr string
	var err error

	// don't continue running any more test steps if previous assertions have failed
	if t.Failed() {
		testTaskError(t, "TEST FAILED")
		t.FailNow()
	}

	if !strings.Contains(command, "-v") {
		command += " -v"
	}

	if len(cfgs) > 1 {
		t.Logf("you can only specify one runConfig test config, provided %d", len(cfgs))
		t.FailNow()
	}

	var cfg runConfig
	if len(cfgs) == 1 {
		cfg = cfgs[0]
	}

	if cfg.timeout == 0 {
		cfg.timeout = 60 * time.Second
	}

	if cfg.env == nil {
		cfg.env = make(map[string]string)
	}

	if cfg.commentary != "" {
		testTaskInfo(t, fmt.Sprintf("--> task: %s", cfg.commentary))
	}
	testTaskInfo(t, fmt.Sprintf("    running quill %s", command))

	runWithTimeout(t, cfg.timeout, func(t testing.TB) {
		stdout, stderr, err = _runQuill(t, cfg, command)
	}, nil)

	if *showStdout || *showStderr {
		if *showStderr {
			testTaskInfo(t, "quill stderr:")
			fmt.Println(strings.TrimSpace(stderr))
		}
		if *showStdout {
			testTaskInfo(t, "quill stdout:")
			fmt.Println(strings.TrimSpace(stdout))
		}

		if err != nil {
			testTaskError(t, fmt.Sprintf("<exit WITH error: %s>", err.Error()))
		} else {
			testTaskInfo(t, "<exit without error>")
		}
	}

	if err != nil {
		err = fmt.Errorf("STDOUT: %s\nSTDERR: %s\nERROR: %w", stdout, stderr, err)
	}

	return stdout, stderr, err
}

func testTaskInfo(t testing.TB, tsk string) {
	if *detail {
		//t.Log(tsk)
		fmt.Printf("    %s %s\n", color.Bold.Render(color.Blue.Render("[test log]")), color.OpItalic.Render(color.Blue.Render(tsk)))
	}
}

func testTaskError(t testing.TB, err string) {
	if *detail {
		//t.Log(tsk)
		fmt.Printf("    %s %s\n", color.Bold.Render(color.Red.Render("[test ERROR]")), color.OpItalic.Render(color.Red.Render(err)))
	}
}

func runWithTimeout(t testing.TB, timeout time.Duration, test func(testing.TB), cleanup func()) {
	done := make(chan bool)
	go func() {
		defer func() { done <- true }()
		test(t)
	}()

	select {
	case <-time.After(timeout):
		if cleanup != nil {
			cleanup()
		}
		t.Fatal("test timed out")
	case <-done:
	}
}

func _runQuill(t testing.TB, cfg runConfig, args ...string) (string, string, error) {
	var splitArgs []string
	for _, c := range args {
		parts := []string{}
		quoted := false
		for _, part := range strings.Split(c, " ") {
			// deal with quoted values
			switch {
			case strings.HasPrefix(part, "'") && strings.HasSuffix(part, "'"):
				parts = append(parts, strings.Trim(part, "'"))
			case strings.HasPrefix(part, "'"):
				parts = append(parts, strings.TrimPrefix(part, "'"))
				quoted = true
			case quoted && strings.HasSuffix(part, "'"):
				parts[len(parts)-1] = parts[len(parts)-1] + " " + strings.TrimSuffix(part, "'")
				quoted = false
			case quoted:
				parts[len(parts)-1] = parts[len(parts)-1] + " " + part
			default:
				parts = append(parts, part)
			}
		}

		splitArgs = append(splitArgs, parts...)
	}
	cmd := getQuillCommand(t, splitArgs...)

	if cfg.stdin != nil {
		cmd.Stdin = cfg.stdin
	}

	return runCommand(cmd, cfg.env)
}

func getQuillCommand(t testing.TB, args ...string) *exec.Cmd {
	return exec.Command(getBinaryLocation(t), args...)
}

func getBinaryLocation(t testing.TB) string {
	if os.Getenv("QUILL_BINARY_LOCATION") != "" {
		// QUILL_BINARY_LOCATION is the absolute path to the snapshot binary
		return os.Getenv("QUILL_BINARY_LOCATION")
	}
	return getBinaryLocationByOS(t, runtime.GOOS)
}

func getBinaryLocationByOS(t testing.TB, goOS string) string {
	// note: for amd64 we need to update the snapshot location with the v1 suffix
	// see : https://goreleaser.com/customization/build/#why-is-there-a-_v1-suffix-on-amd64-builds
	archPath := runtime.GOARCH
	if runtime.GOARCH == "amd64" {
		archPath = fmt.Sprintf("%s_v1", archPath)
	}
	// note: there is a subtle - vs _ difference between these versions
	switch goOS {
	case "darwin", "linux":
		return path.Join(repoRoot(t), fmt.Sprintf("snapshot/%s-build_%s_%s/quill", goOS, goOS, archPath))
	default:
		t.Fatalf("unsupported OS: %s", runtime.GOOS)
	}
	return ""
}

func repoRoot(t testing.TB) string {
	t.Helper()
	root, err := exec.Command("git", "rev-parse", "--show-toplevel").Output()
	if err != nil {
		t.Fatalf("unable to find repo root dir: %+v", err)
	}
	absRepoRoot, err := filepath.Abs(strings.TrimSpace(string(root)))
	if err != nil {
		t.Fatal("unable to get abs path to repo root:", err)
	}
	return absRepoRoot
}

func runCommand(cmd *exec.Cmd, env map[string]string) (string, string, error) {
	if env != nil {
		cmd.Env = append(os.Environ(), envMapToSlice(env)...)
	}
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	// ignore errors since this may be what the test expects
	err := cmd.Run()

	if cmd.ProcessState.ExitCode() != 0 && err == nil {
		err = fmt.Errorf("non-0 exit code")
	}

	return stdout.String(), stderr.String(), err
}

func envMapToSlice(env map[string]string) (envList []string) {
	for key, val := range env {
		if key == "" {
			continue
		}
		envList = append(envList, fmt.Sprintf("%s=%s", key, val))
	}
	return
}

func checkAssertions(t testing.TB, stdout, stderr string, err error, assertions ...trait.Assertion) {
	t.Helper()

	for _, traitFn := range assertions {
		traitFn(t, stdout, stderr, err)
	}

	if t.Failed() {
		// why check the inverse case? so we don't show this output twice
		if !*showStderr {
			testTaskInfo(t, "quill stderr:")
			fmt.Println(strings.TrimSpace(stderr))
		}
		if !*showStdout {
			testTaskInfo(t, "quill stdout:")
			fmt.Println(strings.TrimSpace(stdout))
		}
		testTaskError(t, "TEST FAILED")
		t.FailNow()
	}
}
