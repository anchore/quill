package test

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"testing"
)

func AssertBinarySigned(t *testing.T, path string) {
	// TODO: assert specific traits from debug output
	runCodesignVerify(t, path)
}

func runCodesignVerify(t testing.TB, path string) string {
	cmd := exec.Command("codesign", "-d", "--verbose=6", "--verify", path)
	stdout, stderr := runCommand(cmd, nil)
	if cmd.ProcessState.ExitCode() != 0 {
		t.Log("STDOUT", stdout)
		t.Log("STDERR", stderr)
		t.Log("codesign verify failed")
		t.Fail()
	}
	return stdout
}

func runCodesignShow(t testing.TB, path string) string {
	cmd := exec.Command("codesign", "-d", "--verbose=6", path)
	stdout, stderr := runCommand(cmd, nil)
	if cmd.ProcessState.ExitCode() != 0 {
		t.Log("STDOUT", stdout)
		t.Log("STDERR", stderr)
		t.Log("codesign show failed")
		t.Fail()
	}
	return stdout
}

func runCommand(cmd *exec.Cmd, env map[string]string) (string, string) {
	if env != nil {
		cmd.Env = append(os.Environ(), envMapToSlice(env)...)
	}
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	// ignore errors since this may be what the test expects
	cmd.Run()

	return stdout.String(), stderr.String()
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
