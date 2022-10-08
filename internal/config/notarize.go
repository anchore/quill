package config

import "github.com/spf13/viper"

type notarize struct {
	Issuer       string `yaml:"issuer" json:"issuer" mapstructure:"issuer"`
	PrivateKeyID string `yaml:"key-id" json:"key-id" mapstructure:"key-id"`
	PrivateKey   string `yaml:"key" json:"key" mapstructure:"key"`
}

func (cfg notarize) loadDefaultValues(v *viper.Viper) {
	v.SetDefault("notarize.issuer", "")
	v.SetDefault("notarize.key-id", "")
	v.SetDefault("notarize.key", "")
}
