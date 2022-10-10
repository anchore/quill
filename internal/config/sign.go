package config

import "github.com/spf13/viper"

type sign struct {
	Identity     string `yaml:"identity" json:"identity" mapstructure:"identity"`
	PrivateKey   string `yaml:"key" json:"key" mapstructure:"key"`
	Password     string `yaml:"password" json:"password" mapstructure:"password"`
	Certificates string `yaml:"cert" json:"cert" mapstructure:"cert"`
}

func (cfg sign) loadDefaultValues(v *viper.Viper) {
	v.SetDefault("sign.password", "")
}
