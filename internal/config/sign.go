package config

import "github.com/spf13/viper"

type sign struct {
	Identity     string `yaml:"identity" json:"identity" mapstructure:"identity"`
	PrivateKey   string `yaml:"key" json:"key" mapstructure:"key"`
	Password     string `yaml:"-" json:"-" mapstructure:"password"`
	Certificates string `yaml:"certs" json:"certs" mapstructure:"certs"`
	// Chain        string `yaml:"chain" json:"chain" mapstructure:"chain"`
	//RequireChain bool `yaml:"require-chain" json:"require-chain" mapstructure:"require-chain"`
}

func (cfg sign) loadDefaultValues(v *viper.Viper) {
	v.SetDefault("sign.identity", "")
	v.SetDefault("sign.key", "")
	v.SetDefault("sign.password", "")
	v.SetDefault("sign.certs", "")
	// v.SetDefault("sign.chain", "")
	//v.SetDefault("sign.require-chain", true)
}
