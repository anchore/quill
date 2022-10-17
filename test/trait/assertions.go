package trait

import (
	"encoding/json"
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/acarl005/stripansi"
	"github.com/stretchr/testify/require"
)

type Assertion func(tb testing.TB, stdout, stderr string, err error)

func AssertFileOutput(tb testing.TB, path string, assertions ...Assertion) Assertion {
	tb.Helper()

	return func(tb testing.TB, _, stderr string, e error) {
		content, err := os.ReadFile(path)
		require.NoError(tb, err)
		contentStr := string(content)

		for _, assertion := range assertions {
			// treat the file content as stdout
			assertion(tb, contentStr, stderr, e)
		}
	}
}

func AssertJSONReport(tb testing.TB, stdout, _ string, _ error) {
	tb.Helper()
	var data interface{}

	if err := json.Unmarshal([]byte(stdout), &data); err != nil {
		tb.Errorf("expected to find a JSON report, but was unmarshalable: %+v", err)
	}
}

func AssertTableReport(tb testing.TB, stdout, _ string, _ error) {
	tb.Helper()
	for _, c := range []string{"┌", "└", "┐", "┘"} {
		if !strings.Contains(stdout, c) {
			tb.Errorf("expected to find a table report, but did not")
		}
	}
}

func AssertStdoutRowContains(strs ...string) Assertion {
	return func(tb testing.TB, stdout, _ string, _ error) {
		tb.Helper()
	nextLine:
		for _, line := range strings.Split(stdout, "\n") {
			for _, s := range strs {
				if !strings.Contains(line, s) {
					continue nextLine
				}
			}
			// we've found all target strings, bail!
			return
		}
		tb.Errorf("could not find a single row with all elements: %s", strs)
	}
}

func AssertStderrRowContains(strs ...string) Assertion {
	return func(tb testing.TB, _, stderr string, _ error) {
		tb.Helper()
	nextLine:
		for _, line := range strings.Split(stderr, "\n") {
			for _, s := range strs {
				if !strings.Contains(line, s) {
					continue nextLine
				}
			}
			// we've found all target strings, bail!
			return
		}
		tb.Errorf("could not find a single row with all elements: %s", strs)
	}
}

func AssertLoggingLevel(level string) Assertion {
	// match examples:
	//  "[0000]  INFO"
	//  "[0012] DEBUG"
	logPattern := regexp.MustCompile(`(?m)^\[\d\d\d\d\]\s+` + strings.ToUpper(level))
	return func(tb testing.TB, _, stderr string, _ error) {
		tb.Helper()
		if !logPattern.MatchString(stripansi.Strip(stderr)) {
			tb.Errorf("output did not indicate the %q logging level", level)
		}
	}
}

func AssertNotInOutput(data string) Assertion {
	return func(tb testing.TB, stdout, stderr string, _ error) {
		tb.Helper()
		if strings.Contains(stripansi.Strip(stderr), data) {
			tb.Errorf("data=%q was found in stderr, but should not have been there", data)
		}
		if strings.Contains(stripansi.Strip(stdout), data) {
			tb.Errorf("data=%q was found in stdout, but should not have been there", data)
		}
	}
}

func AssertInOutput(data string) Assertion {
	return func(tb testing.TB, stdout, stderr string, _ error) {
		tb.Helper()
		if !strings.Contains(stripansi.Strip(stderr), data) && !strings.Contains(stripansi.Strip(stdout), data) {
			tb.Errorf("data=%q was NOT found in any output, but should have been there", data)
		}
	}
}

func AssertRegexInOutput(re *regexp.Regexp) Assertion {
	return func(tb testing.TB, stdout, stderr string, _ error) {
		tb.Helper()
		stderrBy := []byte(stripansi.Strip(stderr))
		stdoutBy := []byte(stripansi.Strip(stdout))

		if !re.Match(stderrBy) && !re.Match(stdoutBy) {
			tb.Errorf("regexp=%q was NOT found in any output, but should have been there", re.String())
		}
	}
}

func AssertInStdout(data string) Assertion {
	return func(tb testing.TB, stdout, _ string, _ error) {
		tb.Helper()
		if !strings.Contains(stripansi.Strip(stdout), data) {
			tb.Errorf("data=%q was NOT found in stdout, but should have been there", data)
		}
	}
}

func AssertInStderr(data string) Assertion {
	return func(tb testing.TB, _, stderr string, _ error) {
		tb.Helper()
		if !strings.Contains(stripansi.Strip(stderr), data) {
			tb.Errorf("data=%q was NOT found in stderr, but should have been there", data)
		}
	}
}

func AssertStdoutLengthGreaterThan(length uint) Assertion {
	return func(tb testing.TB, stdout, _ string, _ error) {
		tb.Helper()
		if uint(len(stdout)) < length {
			tb.Errorf("not enough output (expected at least %d, got %d)", length, len(stdout))
		}
	}
}

func AssertFailingReturnCode(tb testing.TB, _, _ string, e error) {
	tb.Helper()
	if e == nil {
		tb.Error("expected a failure but got none")
	}
}

func AssertSuccessfulReturnCode(tb testing.TB, _, _ string, e error) {
	tb.Helper()
	if e != nil {
		tb.Errorf("expected no failure but got err=%+v", e)
	}
}

func AssertFileExists(file string) Assertion {
	return func(tb testing.TB, _, _ string, _ error) {
		tb.Helper()
		if _, err := os.Stat(file); err != nil {
			tb.Errorf("expected file to exist %s", file)
		}
	}
}
