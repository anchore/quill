package main

import (
	"github.com/anchore/clio"
	"github.com/anchore/quill/cmd/quill/cli"
	"github.com/anchore/quill/internal"
)

const valueNotProvided = "[not provided]"

// all variables here are provided as build-time arguments, with clear default values
var version = valueNotProvided
var gitCommit = valueNotProvided
var gitDescription = valueNotProvided
var buildDate = valueNotProvided

func main() {
	app := cli.New(
		clio.Identification{
			Name:           internal.ApplicationName,
			Version:        version,
			GitCommit:      gitCommit,
			GitDescription: gitDescription,
			BuildDate:      buildDate,
		},
	)

	app.Run()
}
