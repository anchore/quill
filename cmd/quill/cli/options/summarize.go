package options

import (
	"fmt"
	"reflect"
	"strings"

	"github.com/iancoleman/strcase"

	"github.com/anchore/quill/internal"
	"github.com/anchore/quill/internal/utils"
)

func Summarize(itf interface{}, currentPath []string) string {
	var desc []string

	t := reflect.TypeOf(itf)
	v := reflect.ValueOf(itf)

	if t.Kind() == reflect.Struct {
		for i := 0; i < t.NumField(); i++ {
			field := t.Field(i)
			description := field.Tag.Get("description")
			yamlName := field.Tag.Get("yaml")

			tag := field.Tag.Get("mapstructure")
			switch tag {
			case "-", "":
				continue
			}

			fieldVal := v.Field(i)

			var newPath []string
			newPath = append(newPath, currentPath...)
			newPath = append(newPath, tag)

			envVar := strcase.ToScreamingSnake(strings.Join(append([]string{internal.ApplicationName}, newPath...), "_"))

			if description != "" {
				var section string
				section += fmt.Sprintf("# %s (env var: %q)\n", description, envVar)

				var val string
				switch field.Type.Kind() {
				case reflect.String:
					val = fmt.Sprintf("%q", fieldVal)
				default:
					val = fmt.Sprintf("%+v", fieldVal)
				}

				section += fmt.Sprintf("%s: %s", yamlName, val)

				desc = append(desc, section)
			} else {
				d := Summarize(fieldVal.Interface(), newPath)
				if d != "" {
					section := yamlName + ":\n" + utils.Indent(d, strings.Repeat("  ", len(newPath)))
					desc = append(desc, strings.TrimSpace(section))
				}
			}
		}
	}

	if len(desc) == 0 {
		return ""
	}

	return strings.Join(desc, "\n\n")
}
