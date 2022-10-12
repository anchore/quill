package application

// type Sign struct {
//	Identity     string `yaml:"identity" json:"identity" mapstructure:"identity"`
//	PrivateKey   string `yaml:"key" json:"key" mapstructure:"key"`
//	Password     string `yaml:"password" json:"password" mapstructure:"password"`
//	Certificates string `yaml:"cert" json:"cert" mapstructure:"cert"`
//}
//
// func (cfg Sign) loadDefaultValues(v *viper.Viper) {
//	v.SetDefault("Sign.password", cfg.Password)
//}
//
// func (cfg *Sign) redact() {
//	if cfg.Password != "" {
//		cfg.Password = redacted
//	}
//	if cfg.PrivateKey != "" {
//		cfg.PrivateKey = redacted
//	}
//}
