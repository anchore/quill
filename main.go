package main

import (
	"fmt"
	"os"

	"github.com/anchore/quill/cmd"
	"github.com/gookit/color"
)

func main() {
	if err := cmd.NewCli().Execute(); err != nil {
		fmt.Fprintln(os.Stderr, color.Red.Sprint(err.Error()))
		os.Exit(1)
	}
}
