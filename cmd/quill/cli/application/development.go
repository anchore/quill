package application

import "github.com/spf13/viper"

type Development struct {
	ProfileCPU bool `yaml:"profile-cpu" json:"profile-cpu" mapstructure:"profile-cpu"`
	ProfileMem bool `yaml:"profile-mem" json:"profile-mem" mapstructure:"profile-mem"`
}

func (c Development) loadDefaultValues(v *viper.Viper) {
	v.SetDefault("dev.profile-cpu", c.ProfileCPU) // zero-value (false) or the current instance value
	v.SetDefault("dev.profile-mem", c.ProfileMem) // zero-value (false) or the current instance value
}
