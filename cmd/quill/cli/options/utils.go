package options

import (
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/anchore/quill/internal/log"
)

func FormatPositionalArgsHelp(args map[string]string) string {
	var keys []string
	for k := range args {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var ret string
	for _, name := range keys {
		val := args[name]
		if val == "" {
			continue
		}
		ret += fmt.Sprintf("  %s:  %s\n", name, val)
	}
	if ret == "" {
		return ret
	}
	return "Arguments:\n" + strings.TrimSuffix(ret, "\n")
}

func redactNonFileOrEnvHint(value string) {
	if strings.HasPrefix(value, "env:") {
		// this is an env hint, the real value will be read downstream of config processing
		return
	}
	if _, err := os.Stat(value); err == nil {
		// the file exists
		return
	}
	// path does not exist OR there was an access issue and we cannot verify... either way, redact
	log.Redact(value)
}
