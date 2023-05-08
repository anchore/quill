package application

import (
	"github.com/anchore/go-logger"
	"gopkg.in/yaml.v2"
)

// Config is the main application configuration.
type Config struct {
	ConfigPath string      `yaml:"config,omitempty" json:"config"` // the location where the application config was read from (either from -c or discovered while loading)
	Dev        Development `yaml:"dev" json:"dev" mapstructure:"dev"`
	Log        Logging     `yaml:"log" json:"log" mapstructure:"log"` // all logging-related options

	DisableLoadFromDisk bool `yaml:"-" json:"-" mapstructure:"-"`
}

func DefaultConfig() *Config {
	return &Config{
		Log: Logging{
			Level: logger.WarnLevel,
		},
	}
}

func (cfg Config) String() string {
	// yaml is pretty human friendly (at least when compared to json)
	appCfgStr, err := yaml.Marshal(&cfg)

	if err != nil {
		return err.Error()
	}

	return string(appCfgStr)
}
