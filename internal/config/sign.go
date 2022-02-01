package config

import "github.com/spf13/viper"

type sign struct {
	Identity    string `yaml:"identity" json:"identity" mapstructure:"identity"`
	PrivateKey  string `yaml:"key" json:"key" mapstructure:"key"`
	Password    string `yaml:"-" json:"-" mapstructure:"password"`
	Certificate string `yaml:"cert" json:"cert" mapstructure:"cert"`
}

func (cfg sign) loadDefaultValues(v *viper.Viper) {
	v.SetDefault("sign.identity", "")
	v.SetDefault("sign.key", "")
	v.SetDefault("sign.password", "")
	v.SetDefault("sign.cert", "")
}
