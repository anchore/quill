package main

import (
	"fmt"
	"os"

	"github.com/gookit/color"

	"github.com/anchore/quill/cmd"
)

func main() {
	if err := cmd.NewCli().Execute(); err != nil {
		fmt.Fprintln(os.Stderr, color.Red.Sprint(err.Error()))
		os.Exit(1)
	}
}
