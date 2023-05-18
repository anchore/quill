package commands

import (
	"context"
	"errors"
	"fmt"

	"github.com/spf13/cobra"
	"software.sslmate.com/src/go-pkcs12"

	"github.com/anchore/clio"
	"github.com/anchore/quill/cmd/quill/cli/options"
	"github.com/anchore/quill/internal/bus"
	"github.com/anchore/quill/internal/log"
	"github.com/anchore/quill/quill/pki/load"
)

func loadP12Interactively(p12Path, password string) (*load.P12Contents, error) {
	p12Content, err := load.P12(p12Path, password)
	if err == nil {
		return p12Content, nil
	}

	if !errors.Is(err, load.ErrNeedPassword) {
		return nil, err
	}

	by, err := load.BytesFromFileOrEnv(p12Path)
	if err != nil {
		return nil, fmt.Errorf("unable to read p12 bytes: %w", err)
	}

	prompter := bus.PromptForInput("Enter P12 password:", true)
	newPassword, err := prompter.Response(context.Background())
	if err != nil {
		return nil, fmt.Errorf("unable to get password from prompt: %w", err)
	}

	log.Redact(newPassword)

	key, cert, certs, err := pkcs12.DecodeChain(by, newPassword)
	if err != nil {
		return nil, fmt.Errorf("unable to decode p12 file: %w", err)
	}

	return &load.P12Contents{
		PrivateKey:   key,
		Certificate:  cert,
		Certificates: certs,
	}, nil
}

func async(f func() error) <-chan error {
	errs := make(chan error)
	go func() {
		defer close(errs)
		if err := f(); err != nil {
			errs <- err
		}
		bus.Exit()
	}()

	return errs
}

func chainArgs(processors ...func(cmd *cobra.Command, args []string) error) func(cmd *cobra.Command, args []string) error {
	return func(cmd *cobra.Command, args []string) error {
		for _, p := range processors {
			if err := p(cmd, args); err != nil {
				return err
			}
		}
		return nil
	}
}

func commonConfiguration(app clio.Application, cmd *cobra.Command, opts options.Interface) {
	if opts != nil {
		opts.AddFlags(cmd.Flags())

		if app != nil {
			// we want to be able to attach config binding information to the help output
			cmd.SetHelpFunc(func(cmd *cobra.Command, args []string) {
				_ = app.Setup(opts)(cmd, args)
				cmd.Parent().HelpFunc()(cmd, args)
			})
		}
	}

	cmd.SilenceUsage = true
	cmd.SilenceErrors = true
	cmd.SetHelpTemplate(`{{if (or .Long .Short)}}{{.Long}}{{if not .Long}}{{.Short}}{{end}}

{{end}}Usage:{{if .Runnable}}
  {{.UseLine}}{{end}}{{if .HasAvailableSubCommands}}
  {{.CommandPath}} [command]{{end}}{{if .HasExample}}

{{.Example}}{{end}}{{if gt (len .Aliases) 0}}

Aliases:
  {{.NameAndAliases}}{{end}}{{if .HasAvailableSubCommands}}

Available Commands:{{range .Commands}}{{if (or .IsAvailableCommand (eq .Name "help"))}}
  {{rpad .Name .NamePadding }} {{.Short}}{{end}}{{end}}{{end}}{{if .HasAvailableLocalFlags}}

{{if not .CommandPath}}Global {{end}}Flags:
{{.LocalFlags.FlagUsages | trimTrailingWhitespaces}}{{end}}{{if (and .HasAvailableInheritedFlags (not .CommandPath))}}

Global Flags:
{{.InheritedFlags.FlagUsages | trimTrailingWhitespaces}}{{end}}{{if .HasHelpSubCommands}}

Additional help topics:{{range .Commands}}{{if .IsAdditionalHelpTopicCommand}}
  {{rpad .CommandPath .CommandPathPadding}} {{.Short}}{{end}}{{end}}{{end}}{{if .HasAvailableSubCommands}}

Use "{{if .CommandPath}}{{.CommandPath}} {{end}}[command] --help" for more information about a command.{{end}}
`)
}
