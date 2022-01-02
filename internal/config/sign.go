package config

import "github.com/spf13/viper"

type sign struct {
	PrivateKey  bool `yaml:"key" json:"key" mapstructure:"key"`
	Certificate bool `yaml:"cert" json:"cert" mapstructure:"cert"`
}

func (cfg sign) loadDefaultValues(v *viper.Viper) {
	v.SetDefault("sign.key", "")
	v.SetDefault("sign.cert", "")
}
