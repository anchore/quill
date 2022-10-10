package log

import (
	"fmt"
	"strings"
	"sync"

	"github.com/scylladb/go-set/strset"

	"github.com/anchore/go-logger"
)

var (
	_           logger.Logger = (*redactingLogger)(nil)
	_redactions               = strset.New()
	lock                      = &sync.RWMutex{}
)

// all instances of the redaction logger share the same set of things that should be redacted, no matter when the
// end user registers something to be redacted.
func globalStaticRedactions() []string {
	lock.RLock()
	defer lock.RUnlock()
	return _redactions.List()
}

func Redact(value string) {
	lock.Lock()
	defer lock.Unlock()
	if len(value) <= 1 {
		// smallest possible redaction string is larger than 1 character
		return
	}
	_redactions.Add(value)
}

type redactingLogger struct {
	log        logger.MessageLogger
	redactions func() []string
}

func newRedactingLogger(log logger.MessageLogger, redactor func() []string) *redactingLogger {
	return &redactingLogger{
		log:        log,
		redactions: redactor,
	}
}

func (r *redactingLogger) Errorf(format string, args ...interface{}) {
	r.log.Errorf(r.redactString(format), r.redactFields(args)...)
}

func (r *redactingLogger) Error(args ...interface{}) {
	r.log.Error(r.redactFields(args)...)
}

func (r *redactingLogger) Warnf(format string, args ...interface{}) {
	r.log.Warnf(r.redactString(format), r.redactFields(args)...)
}

func (r *redactingLogger) Warn(args ...interface{}) {
	r.log.Warn(r.redactFields(args)...)
}

func (r *redactingLogger) Infof(format string, args ...interface{}) {
	r.log.Infof(r.redactString(format), r.redactFields(args)...)
}

func (r *redactingLogger) Info(args ...interface{}) {
	r.log.Info(r.redactFields(args)...)
}

func (r *redactingLogger) Debugf(format string, args ...interface{}) {
	r.log.Debugf(r.redactString(format), r.redactFields(args)...)
}

func (r *redactingLogger) Debug(args ...interface{}) {
	r.log.Debug(r.redactFields(args)...)
}

func (r *redactingLogger) Tracef(format string, args ...interface{}) {
	r.log.Tracef(r.redactString(format), r.redactFields(args)...)
}

func (r *redactingLogger) Trace(args ...interface{}) {
	r.log.Trace(r.redactFields(args)...)
}

func (r *redactingLogger) WithFields(fields ...interface{}) logger.MessageLogger {
	if l, ok := r.log.(logger.FieldLogger); ok {
		return newRedactingLogger(l.WithFields(r.redactFields(fields)...), r.redactions)
	}
	return r
}

func (r *redactingLogger) Nested(fields ...interface{}) logger.Logger {
	if l, ok := r.log.(logger.NestedLogger); ok {
		return newRedactingLogger(l.Nested(r.redactFields(fields)...), r.redactions)
	}
	return r
}

func (r *redactingLogger) redactFields(fields []interface{}) []interface{} {
	for i, v := range fields {
		switch vv := v.(type) {
		case string:
			fields[i] = r.redactString(vv)
		case int, int32, int64, int16, int8, float32, float64:
			// don't coerce non-string primitives to different types
			fields[i] = vv
		case logger.Fields:
			for kkk, vvv := range vv {
				delete(vv, kkk) // this key may have data that should be redacted
				redactedKey := r.redactString(kkk)

				switch vvvv := vvv.(type) {
				case string:
					vv[redactedKey] = r.redactString(vvvv)
				case int, int32, int64, int16, int8, float32, float64:
					// don't coerce non-string primitives to different types (but still redact the key)
					vv[redactedKey] = vvvv
				default:
					vv[redactedKey] = r.redactString(fmt.Sprintf("%+v", vvvv))
				}
			}
			fields[i] = vv
		default:
			// coerce to a string and redact
			fields[i] = r.redactString(fmt.Sprintf("%+v", vv))
		}
	}
	return fields
}

func (r *redactingLogger) redactString(str string) string {
	for _, s := range r.redactions() {
		// note: we don't use the length of the redaction string to determine the replacement string, as even the length could be considered sensitive
		str = strings.ReplaceAll(str, s, strings.Repeat("*", 7))
	}
	return str
}
