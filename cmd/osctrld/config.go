package main

import (
	"github.com/rs/zerolog/log"
	"github.com/spf13/viper"
)

const (
	configurationKey = "osctrld"
)

// Configuration holds all configuration values for osctrld.
// Supports both YAML (default) and JSON config files.
type Configuration struct {
	Secret        string `json:"secret" yaml:"secret" mapstructure:"secret"`
	SecretFile    string `json:"secretFile" yaml:"secretFile" mapstructure:"secretFile"`
	FlagFile      string `json:"flags" yaml:"flags" mapstructure:"flags"`
	CertFile      string `json:"cert" yaml:"cert" mapstructure:"cert"`
	EnrollScript  string `json:"enrollScript" yaml:"enrollScript" mapstructure:"enrollScript"`
	RemoveScript  string `json:"removeScript" yaml:"removeScript" mapstructure:"removeScript"`
	OsqueryPath   string `json:"osquery" yaml:"osquery" mapstructure:"osquery"`
	Environment   string `json:"environment" yaml:"environment" mapstructure:"environment"`
	BaseURL       string `json:"baseurl" yaml:"baseurl" mapstructure:"baseurl"`
	Insecure      bool   `json:"insecure" yaml:"insecure" mapstructure:"insecure"`
	Verbose       bool   `json:"verbose" yaml:"verbose" mapstructure:"verbose"`
	Force         bool   `json:"force" yaml:"force" mapstructure:"force"`
	LogFormat     string `json:"logFormat" yaml:"logFormat" mapstructure:"logFormat"`
	Interval      int    `json:"interval" yaml:"interval" mapstructure:"interval"`
	ExtensionsDir string `json:"extensionsDir" yaml:"extensionsDir" mapstructure:"extensionsDir"`
}

func loadConfiguration(file string, verbose bool) (Configuration, error) {
	var cfg Configuration
	log.Debug().Str("path", file).Msg("loading configuration")
	viper.SetConfigFile(file)
	if err := viper.ReadInConfig(); err != nil {
		return cfg, err
	}
	configRaw := viper.Sub(configurationKey)
	if err := configRaw.Unmarshal(&cfg); err != nil {
		return cfg, err
	}
	return cfg, nil
}
