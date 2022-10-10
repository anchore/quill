package log

import (
	"bytes"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/go-logger"
	"github.com/anchore/go-logger/adapter/logrus"
)

func Test_RedactingLogger(t *testing.T) {
	tests := []struct {
		name   string
		redact []string
	}{
		{
			name:   "single value",
			redact: []string{"joe"},
		},
		{
			name:   "multi value",
			redact: []string{"bob", "alice"},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			out, err := logrus.New(logrus.Config{
				Level: logger.TraceLevel,
			})
			require.NoError(t, err)

			buff := bytes.Buffer{}
			out.(logger.Controller).SetOutput(&buff)

			redactor := newRedactingLogger(out, func() []string { return test.redact })

			var fieldObj = make(logger.Fields)
			for _, v := range test.redact {
				fieldObj[v] = v
			}

			format := ""
			var fields []interface{}
			for _, v := range test.redact {
				fields = append(fields, v)
				format += "%s"
			}

			fields = append(fields, 3)
			format += "%d"

			fields = append(fields, int32(3))
			format += "%d"

			fields = append(fields, 3.2)
			format += "%f"

			fields = append(fields, float32(4.3))
			format += "%f"

			fields = append(fields, fieldObj)
			format += "%+v"

			var interlacedFields []interface{}
			for i, f := range fields {
				interlacedFields = append(interlacedFields, fmt.Sprintf("%d", i), f)
			}

			nestedFieldLogger := redactor.Nested(interlacedFields...).WithFields(interlacedFields...)

			nestedFieldLogger.Tracef(format, fields...)
			nestedFieldLogger.Trace(fields...)

			nestedFieldLogger.Debugf(format, fields...)
			nestedFieldLogger.Debug(fields...)

			nestedFieldLogger.Infof(format, fields...)
			nestedFieldLogger.Info(fields...)

			nestedFieldLogger.Warnf(format, fields...)
			nestedFieldLogger.Warn(fields...)

			nestedFieldLogger.Errorf(format, fields...)
			nestedFieldLogger.Error(fields...)

			result := buff.String()

			// this is a string indicator that we've coerced an instance to a new type that does not match the format type (e.g. %d)
			assert.NotContains(t, result, "%")

			assert.NotEmpty(t, result)
			for _, v := range test.redact {
				assert.NotContains(t, result, v)
			}
		})
	}
}
