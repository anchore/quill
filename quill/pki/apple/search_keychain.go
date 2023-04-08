package apple

import (
	"github.com/anchore/quill/internal/log"
	"os/exec"
	"strings"
)

func SearchKeychain(certCNSearch, keychainPath string) (string, error) {
	contents, err := run("security", "find-certificate", "-a", "-c", certCNSearch, "-p", keychainPath)
	if err != nil {
		return "", err
	}
	return contents, nil
}

func run(args ...string) (string, error) {
	baseCmd := args[0]
	cmdArgs := args[1:]

	log.Tracef("running command: %q", strings.Join(args, " "))

	cmd := exec.Command(baseCmd, cmdArgs...)
	out, err := cmd.Output()
	if err != nil {
		return "", err
	}

	return string(out), nil
}
