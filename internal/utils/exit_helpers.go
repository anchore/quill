package utils

import (
	"os"

	"github.com/gookit/color"
)

func FatalOnError(err error, msg string) {
	if err != nil {
		ExitWithErrorf("%s: %v", msg, err)
	}
}

func ExitWithErrorf(format string, args ...interface{}) {
	color.Red.Printf(format+"\n", args...)
	os.Exit(1)
}
