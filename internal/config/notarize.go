package config

type notarize struct {
	Issuer       string `yaml:"issuer" json:"issuer" mapstructure:"issuer"`
	PrivateKeyID string `yaml:"key-id" json:"key-id" mapstructure:"key-id"`
	PrivateKey   string `yaml:"key" json:"key" mapstructure:"key"`
	Wait         bool   `yaml:"wait" json:"wait" mapstructure:"wait"`
}
