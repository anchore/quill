package extract

import (
	"bytes"
	"strings"
	"text/template"
)

func tprintf(tmpl string, data interface{}) string {
	t := template.Must(template.New("").Parse(tmpl))
	buf := &bytes.Buffer{}
	if err := t.Execute(buf, data); err != nil {
		// TODO
		panic(err)
	}
	return buf.String()
}

func doIndent(s string, indent string) string { //nolint:unparam
	var lines []string
	// for _, line := range strings.Split(strings.TrimRight(s, "\n"), "\n") {
	for _, line := range strings.Split(s, "\n") {
		lines = append(lines, indent+line)
	}
	return strings.TrimRight(strings.Join(lines, "\n"), " ")
}
