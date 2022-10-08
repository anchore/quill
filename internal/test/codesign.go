package test

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/acarl005/stripansi"
	"github.com/stretchr/testify/assert"
)

type OutputAssertion func(tb testing.TB, stdout string)

func AssertContains(data string) OutputAssertion {
	return func(tb testing.TB, stdout string) {
		tb.Helper()
		if !strings.Contains(stripansi.Strip(stdout), data) {
			tb.Errorf("missing debug output: %q", data)
		}
	}
}

func AssertSignedOutput(tb testing.TB, stdout string) {
	tb.Helper()
	if !strings.Contains(stripansi.Strip(stdout), "valid on disk") {
		tb.Error("failed signed assertion: is not valid on disk")
	}
	if !strings.Contains(stripansi.Strip(stdout), "satisfies its Designated Requirement") {
		tb.Error("failed signed assertion: does not satisfy designated requirement")
	}
}

func AssertAgainstCodesignTool(t *testing.T, path string) {
	output := runCodesignVerify(t, path)
	AssertSignedOutput(t, output)
	if t.Failed() {
		t.Logf("signature verification output: \n%s", output)
	}
}

func AssertDebugOutput(t *testing.T, path string, assertions ...OutputAssertion) {
	output := runCodesignShow(t, path)

	for _, traitFn := range assertions {
		traitFn(t, output)
	}

	if t.Failed() {
		t.Logf("signature debug output: \n%s", output)
	}
}

func runCodesignVerify(t testing.TB, path string) string {
	assertCodesignExists(t)
	cmd := exec.Command("codesign", "-vvv", "--verify", "--deep", "--strict", path)
	output := runCommand(t, cmd, nil)
	if cmd.ProcessState.ExitCode() != 0 {
		t.Log(output)
		t.Log("codesign verify failed")
	}
	return output
}

func runCodesignShow(t testing.TB, path string) string {
	assertCodesignExists(t)
	cmd := exec.Command("codesign", "-d", "--verbose=4", path)
	output := runCommand(t, cmd, nil)
	if cmd.ProcessState.ExitCode() != 0 {
		t.Log(output)
		t.Log("codesign show failed")
	}
	return output
}

func runCommand(t testing.TB, cmd *exec.Cmd, env map[string]string) string {
	if env != nil {
		cmd.Env = append(os.Environ(), envMapToSlice(env)...)
	}

	output, err := cmd.CombinedOutput()
	assert.NoError(t, err)

	return string(output)
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

func assertCodesignExists(t testing.TB) {
	if commandExists("codesign") {
		return
	}
	t.Fatalf("codesign is not installed -- which is required for this test")
}

func commandExists(cmd string) bool {
	_, err := exec.LookPath(cmd)
	return err == nil
}
