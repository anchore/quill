/*
Package logger defines the logging interface which is used throughout the library.
*/
package logger

// Logger represents the behavior for logging within the library.
type Logger interface {
	Errorf(format string, args ...interface{})
	Error(args ...interface{})
	Warnf(format string, args ...interface{})
	Warn(args ...interface{})
	Infof(format string, args ...interface{})
	Info(args ...interface{})
	Debugf(format string, args ...interface{})
	Debug(args ...interface{})
}
