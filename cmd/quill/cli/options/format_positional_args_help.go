package options

import (
	"fmt"
	"sort"
	"strings"
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
