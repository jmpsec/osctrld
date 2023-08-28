package main

import (
	"log"

	"github.com/spf13/viper"
)

const (
	configurationKey = "osctrld"
)

// JSONConfiguration to hold all configuration values for osctrld
type JSONConfiguration struct {
	Secret       string `json:"secret"`
	SecretFile   string `json:"secretFile"`
	FlagFile     string `json:"flags"`
	CertFile     string `json:"cert"`
	EnrollScript string `json:"enrollScript"`
	RemoveScript string `json:"removeScript"`
	OsqueryPath  string `json:"osquery"`
	Environment  string `json:"environment"`
	BaseURL      string `json:"baseurl"`
	Insecure     bool   `json:"insecure"`
	Verbose      bool   `json:"verbose"`
	Force        bool   `json:"force"`
}

// Function to load the configuration file and assign to variables
func loadConfiguration(file string, verbose bool) (JSONConfiguration, error) {
	var cfg JSONConfiguration
	if verbose {
		log.Printf("Loading %s", file)
	}
	// Load file and read config
	viper.SetConfigFile(file)
	if err := viper.ReadInConfig(); err != nil {
		return cfg, err
	}
	// Configuration values
	configRaw := viper.Sub(configurationKey)
	if err := configRaw.Unmarshal(&cfg); err != nil {
		return cfg, err
	}
	// No errors!
	return cfg, nil
}
