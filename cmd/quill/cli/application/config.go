package application

import (
	"errors"
	"fmt"
	"path"
	"reflect"

	"github.com/adrg/xdg"
	"github.com/mitchellh/go-homedir"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
	"gopkg.in/yaml.v2"

	"github.com/anchore/quill/cmd/quill/cli/options"
	"github.com/anchore/quill/internal"
)

var ConfigSearchLocations = []string{
	fmt.Sprintf(".%s.yaml", internal.ApplicationName),
	fmt.Sprintf("%s.yaml", internal.ApplicationName),
	fmt.Sprintf(".%s/config.yaml", internal.ApplicationName),
	fmt.Sprintf("~/.%s.yaml", internal.ApplicationName),
	fmt.Sprintf("~/%s.yaml", internal.ApplicationName),
	fmt.Sprintf("$XDG_CONFIG_HOME/%s/config.yaml", internal.ApplicationName),
}

var ErrConfigNotFound = fmt.Errorf("config not found")

type defaultValueLoader interface {
	loadDefaultValues(*viper.Viper)
}

type parser interface {
	parseConfigValues() error
}

// Config is the main application configuration.
type Config struct {
	ConfigPath string      `yaml:"config,omitempty" json:"config"` // the location where the application config was read from (either from -c or discovered while loading)
	Dev        Development `yaml:"dev" json:"dev" mapstructure:"dev"`
	Log        Logging     `yaml:"log" json:"log" mapstructure:"log"` // all logging-related options

	DisableLoadFromDisk bool `yaml:"-" json:"-" mapstructure:"-"`
}

func (cfg *Config) BindFlags(flags *pflag.FlagSet, v *viper.Viper) error {
	options.BindOrExit(v, "config", flags.Lookup("config"))
	options.BindOrExit(v, "verbosity", flags.Lookup("verbose"))
	options.BindOrExit(v, "quiet", flags.Lookup("quiet"))

	return nil
}

// Load populates the given viper object with application configuration discovered on disk
func (cfg *Config) Load(v *viper.Viper) error {
	// read the config from a specified path from the environment (only if not already preconfigured)
	if cfg.ConfigPath == "" {
		// unmarshal only control from viper in order to get config file path
		var control struct {
			ConfigPath string `yaml:"config" json:"config" mapstructure:"config"`
		}
		err := v.Unmarshal(&control)
		if err != nil {
			return fmt.Errorf("unable to unmarshal control section of application config: %w", err)
		}
		if control.ConfigPath != "" {
			cfg.ConfigPath = control.ConfigPath
		}
	}

	// check if user specified config; otherwise read all possible paths
	if !cfg.DisableLoadFromDisk && cfg.ConfigPath != "-" {
		if err := readFromDisk(v, cfg.ConfigPath); err != nil {
			return err
		}
	}

	// load default config values into viper
	cfg.loadDefaultValues(v)

	// unmarshal fully populated viper object onto config
	if err := v.Unmarshal(cfg); err != nil {
		return fmt.Errorf("unable to unmarshal application config: %w", err)
	}

	// Convert all populated config options to their internal application values ex: scope string => scopeOpt source.Scope
	return cfg.parseConfigValues()
}

// init loads the default configuration values into the viper instance (before the config values are read and parsed).
func (cfg Config) loadDefaultValues(v *viper.Viper) {
	// for each field in the configuration struct, see if the field implements the defaultValueLoader interface and invoke it if it does
	value := reflect.ValueOf(cfg)
	for i := 0; i < value.NumField(); i++ {
		// note: the defaultValueLoader method receiver is NOT a pointer receiver.
		if loadable, ok := value.Field(i).Interface().(defaultValueLoader); ok {
			// the field implements defaultValueLoader, call it
			loadable.loadDefaultValues(v)
		}
	}
}

func (cfg *Config) parseConfigValues() error {
	// parse nested config options
	// for each field in the configuration struct, see if the field implements the parser interface
	// note: the app config is a pointer, so we need to grab the elements explicitly (to traverse the address)
	value := reflect.ValueOf(cfg).Elem()
	for i := 0; i < value.NumField(); i++ {
		// note: since the interface method of parser is a pointer receiver we need to get the value of the field as a pointer.
		if parsable, ok := value.Field(i).Addr().Interface().(parser); ok {
			// the field implements parser, call it
			if err := parsable.parseConfigValues(); err != nil {
				return err
			}
		}
	}
	return nil
}

func (cfg Config) String() string {
	// yaml is pretty human friendly (at least when compared to json)
	appCfgStr, err := yaml.Marshal(&cfg)

	if err != nil {
		return err.Error()
	}

	return string(appCfgStr)
}

// readConfig attempts to read the given config path from disk or discover an alternate store location
//

func readFromDisk(v *viper.Viper, configPath string) error {
	var err error
	// use explicitly the given user config
	if configPath != "" {
		v.SetConfigFile(configPath)
		if err := v.ReadInConfig(); err != nil {
			return fmt.Errorf("unable to read application config=%q: %w", configPath, err)
		}
		v.Set("config", v.ConfigFileUsed())
		// don't fall through to other options if the config path was explicitly provided
		return nil
	}

	// start searching for valid configs in order...
	// 1. look for .<appname>.yaml (in the current directory)
	v.AddConfigPath(".")
	v.SetConfigName("." + internal.ApplicationName)
	if err = v.ReadInConfig(); err == nil {
		v.Set("config", v.ConfigFileUsed())
		return nil
	} else if !errors.As(err, &viper.ConfigFileNotFoundError{}) {
		return fmt.Errorf("unable to parse config=%q: %w", v.ConfigFileUsed(), err)
	}

	// 2. look for <appname>.yaml (in the current directory)
	v.AddConfigPath(".")
	v.SetConfigName(internal.ApplicationName)
	if err = v.ReadInConfig(); err == nil {
		v.Set("config", v.ConfigFileUsed())
		return nil
	} else if !errors.As(err, &viper.ConfigFileNotFoundError{}) {
		return fmt.Errorf("unable to parse config=%q: %w", v.ConfigFileUsed(), err)
	}

	// 3. look for .<appname>/config.yaml (in the current directory)
	v.AddConfigPath("." + internal.ApplicationName)
	v.SetConfigName("config")
	if err = v.ReadInConfig(); err == nil {
		v.Set("config", v.ConfigFileUsed())
		return nil
	} else if !errors.As(err, &viper.ConfigFileNotFoundError{}) {
		return fmt.Errorf("unable to parse config=%q: %w", v.ConfigFileUsed(), err)
	}

	// 4. look for ~/.<appname>.yaml && ~/<appname>.yaml
	home, err := homedir.Dir()
	if err == nil {
		v.AddConfigPath(home)
		v.SetConfigName("." + internal.ApplicationName)
		if err = v.ReadInConfig(); err == nil {
			v.Set("config", v.ConfigFileUsed())
			return nil
		} else if !errors.As(err, &viper.ConfigFileNotFoundError{}) {
			return fmt.Errorf("unable to parse config=%q: %w", v.ConfigFileUsed(), err)
		}

		v.SetConfigName(internal.ApplicationName)
		if err = v.ReadInConfig(); err == nil {
			v.Set("config", v.ConfigFileUsed())
			return nil
		} else if !errors.As(err, &viper.ConfigFileNotFoundError{}) {
			return fmt.Errorf("unable to parse config=%q: %w", v.ConfigFileUsed(), err)
		}
	}

	// 5. look for <appname>/config.yaml in xdg locations (starting with xdg home config dir, then moving upwards)
	v.AddConfigPath(path.Join(xdg.ConfigHome, internal.ApplicationName))
	for _, dir := range xdg.ConfigDirs {
		v.AddConfigPath(path.Join(dir, internal.ApplicationName))
	}
	v.SetConfigName("config")
	if err = v.ReadInConfig(); err == nil {
		v.Set("config", v.ConfigFileUsed())
		return nil
	} else if !errors.As(err, &viper.ConfigFileNotFoundError{}) {
		return fmt.Errorf("unable to parse config=%q: %w", v.ConfigFileUsed(), err)
	}
	return nil
}
