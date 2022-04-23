package config

import "github.com/spf13/viper"

type sign struct {
	Identity     string `yaml:"identity" json:"identity" mapstructure:"identity"`
	PrivateKey   string `yaml:"key" json:"key" mapstructure:"key"`
	Password     string `yaml:"-" json:"-" mapstructure:"password"`
	Certificate  string `yaml:"cert" json:"cert" mapstructure:"cert"`
	Chain        string `yaml:"chain" json:"chain" mapstructure:"chain"`
	RequireChain bool   `yaml:"require-chain" json:"require-chain" mapstructure:"require-chain"`
}

func (cfg sign) loadDefaultValues(v *viper.Viper) {
	v.SetDefault("sign.identity", "")
	v.SetDefault("sign.key", "")
	v.SetDefault("sign.password", "")
	v.SetDefault("sign.cert", "")
	v.SetDefault("sign.chain", "")
	v.SetDefault("sign.require-chain", true)
}
