package application

import (
	"github.com/spf13/viper"

	"github.com/anchore/go-logger"
)

// Logging contains all logging-related configuration options available to the user via the application config.
type Logging struct {
	Quiet        bool         `yaml:"quiet" json:"quiet" mapstructure:"quiet" description:"suppress logging output"`         // -q, indicates to not show any status output to stderr
	Verbosity    int          `yaml:"-" json:"-" mapstructure:"verbosity"`                                                   // -v or -vv , controlling which UI (ETUI vs logging) and what the log level should be
	Level        logger.Level `yaml:"level" json:"level" mapstructure:"level" description:"error, warn, info, debug, trace"` // the log level string hint
	FileLocation string       `yaml:"file" json:"file" mapstructure:"file" description:"file to write all loge entries to"`  // the file path to write logs to

	// not implemented upstream
	// Structured   bool         `yaml:"structured" json:"structured" mapstructure:"structured"`                        // show all log entries as JSON formatted strings
}

func (cfg Logging) loadDefaultValues(v *viper.Viper) {
	v.SetDefault("log.level", string(logger.InfoLevel)) // TODO: set to warn in the future
	v.SetDefault("log.file", cfg.FileLocation)
}

func (cfg *Logging) parseConfigValues() error {
	switch {
	case cfg.Quiet:
		// TODO: this is bad: quiet option trumps all other logging options (such as to a file on disk)
		// we should be able to quiet the console logging and leave file logging alone...
		// ... this will be an enhancement for later
		cfg.Level = logger.DisabledLevel

	case cfg.Verbosity > 0:
		// TODO: there is a panic in this function when specifying more verbosity than whats available
		cfg.Level = logger.LevelFromVerbosity(cfg.Verbosity, logger.WarnLevel, logger.InfoLevel, logger.DebugLevel, logger.TraceLevel)

	case cfg.Level != "":
		var err error
		cfg.Level, err = logger.LevelFromString(string(cfg.Level))
		if err != nil {
			return err
		}

		if logger.IsVerbose(cfg.Level) {
			cfg.Verbosity = 1
		}
	default:
		// TODO: set default warn
		cfg.Level = logger.WarnLevel
	}

	return nil
}
