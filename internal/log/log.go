/*
Package log contains the singleton object and helper functions for facilitating logging within the library.
*/
package log

import (
	"github.com/anchore/go-logger/adapter/discard"
)

// Log is the singleton used to facilitate logging internally within
var Log = discard.New()

// Errorf takes a formatted template string and template arguments for the error logging level.
func Errorf(format string, args ...interface{}) {
	Log.Errorf(format, args...)
}

// Error logs the given arguments at the error logging level.
func Error(args ...interface{}) {
	Log.Error(args...)
}

// Warnf takes a formatted template string and template arguments for the warning logging level.
func Warnf(format string, args ...interface{}) {
	Log.Warnf(format, args...)
}

// Warn logs the given arguments at the warning logging level.
func Warn(args ...interface{}) {
	Log.Warn(args...)
}

// Infof takes a formatted template string and template arguments for the info logging level.
func Infof(format string, args ...interface{}) {
	Log.Infof(format, args...)
}

// Info logs the given arguments at the info logging level.
func Info(args ...interface{}) {
	Log.Info(args...)
}

// Debugf takes a formatted template string and template arguments for the debug logging level.
func Debugf(format string, args ...interface{}) {
	Log.Debugf(format, args...)
}

// Debug logs the given arguments at the debug logging level.
func Debug(args ...interface{}) {
	Log.Debug(args...)
}

// Tracef takes a formatted template string and template arguments for the trace logging level.
func Tracef(format string, args ...interface{}) {
	Log.Tracef(format, args...)
}

// Trace logs the given arguments at the trace logging level.
func Trace(args ...interface{}) {
	Log.Trace(args...)
}
