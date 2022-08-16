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
	Secret      string `json:"secret"`
	SecretFile  string `json:"secretFile"`
	FlagFile    string `json:"flagFile"`
	Environment string `json:"environment"`
	URL         string `json:"url"`
	Insecure    bool   `json:"insecure"`
	Verbose     bool   `json:"verbose"`
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
