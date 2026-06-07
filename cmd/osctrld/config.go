package main

import (
	"bytes"
	"fmt"
	"net/url"
	"runtime"
	"strings"

	"github.com/rs/zerolog/log"
	"github.com/spf13/viper"
	"github.com/urfave/cli/v2"
	"gopkg.in/yaml.v3"
)

const (
	configurationKey = "osctrld"
)

const (
	// Default secret file
	defSecretFile = "osquery.secret"
	// Default flag file
	defFlagFile = "osquery.flags"
	// Default certificate
	defCertificate = "osctrl.crt"
	// Default enroll script
	defEnrollScript = appName + "-enroll"
	// Default remove script
	defRemoveScript = appName + "-remove"
	// Script extension for linux/darwin
	shExtension = ".sh"
	// Script extension for windows
	ps1Extension = ".ps1"
	// Default empty value
	defEmptyValue = ""
	// Default osquery path for darwin
	defDarwinPath = "/private/var/osquery/"
	// Default osquery path for linux
	defLinuxPath = "/etc/osquery/"
	// Default osquery path for windows
	defWindowsPath = "C:\\Program Files\\osquery\\"
	// Default log format
	defLogFormat = "text"
	// Default sync interval
	defInterval = 60
)

// Variables for config flags and loaded configuration.
var (
	configFile string
	appConfig  Configuration
	flags      []cli.Flag
	osctrlURLs OsctrlURLs
)

// Configuration holds all configuration values for osctrld.
// Supports both YAML (default) and JSON config files.
type Configuration struct {
	OsctrlSecret      string `json:"osctrlSecret" yaml:"osctrlSecret" mapstructure:"osctrlSecret"`
	OsquerySecretFile string `json:"osquerySecretFile" yaml:"osquerySecretFile" mapstructure:"osquerySecretFile"`
	OsqueryFlagFile   string `json:"osqueryFlagFile" yaml:"osqueryFlagFile" mapstructure:"osqueryFlagFile"`
	OsqueryCertFile   string `json:"osqueryCertFile" yaml:"osqueryCertFile" mapstructure:"osqueryCertFile"`
	EnrollScript      string `json:"enrollScript" yaml:"enrollScript" mapstructure:"enrollScript"`
	RemoveScript      string `json:"removeScript" yaml:"removeScript" mapstructure:"removeScript"`
	OsqueryPath       string `json:"osquery" yaml:"osquery" mapstructure:"osquery"`
	Environment       string `json:"environment" yaml:"environment" mapstructure:"environment"`
	BaseURL           string `json:"baseurl" yaml:"baseurl" mapstructure:"baseurl"`
	Insecure          bool   `json:"insecure" yaml:"insecure" mapstructure:"insecure"`
	Verbose           bool   `json:"verbose" yaml:"verbose" mapstructure:"verbose"`
	Force             bool   `json:"force" yaml:"force" mapstructure:"force"`
	LogFormat         string `json:"logFormat" yaml:"logFormat" mapstructure:"logFormat"`
	Interval          int    `json:"interval" yaml:"interval" mapstructure:"interval"`
	ExtensionsDir     string `json:"extensionsDir" yaml:"extensionsDir" mapstructure:"extensionsDir"`
}

type ConfigurationFile struct {
	Osctrld Configuration `json:"osctrld" yaml:"osctrld"`
}

func defaultConfiguration() Configuration {
	return Configuration{
		OsctrlSecret:      "replace-with-osctrl-enrollment-secret",
		OsquerySecretFile: "/path/to/osquery.secret",
		OsqueryFlagFile:   "/path/to/osquery.flags",
		OsqueryCertFile:   "/path/to/osctrl.crt",
		EnrollScript:      "/path/to/osctrld-enroll.sh",
		RemoveScript:      "/path/to/osctrld-remove.sh",
		OsqueryPath:       "/path/to/osquery/",
		Environment:       "environment_name_or_UUID",
		BaseURL:           "https://osctrl.url",
		Insecure:          false,
		Verbose:           false,
		Force:             false,
		LogFormat:         defLogFormat,
		Interval:          defInterval,
		ExtensionsDir:     "/path/to/extensions/",
	}
}

func buildConfigFlags() []cli.Flag {
	return []cli.Flag{
		&cli.StringFlag{
			Name:        "configuration",
			Aliases:     []string{"c", "conf", "config"},
			Value:       defEmptyValue,
			Usage:       "Configuration file for osctrld to load all necessary values",
			EnvVars:     []string{"OSCTRL_CONFIG"},
			Destination: &configFile,
		},
		&cli.StringFlag{
			Name:        "secret",
			Aliases:     []string{"s"},
			Value:       defEmptyValue,
			Usage:       "osctrl enrollment secret used to authenticate with the osctrl server",
			EnvVars:     []string{"OSCTRL_SECRET"},
			Destination: &appConfig.OsctrlSecret,
		},
		&cli.StringFlag{
			Name:        "environment",
			Aliases:     []string{"e", "env"},
			Value:       defEmptyValue,
			Usage:       "Environment in osctrl to enrolled nodes to",
			EnvVars:     []string{"OSCTRL_ENV"},
			Destination: &appConfig.Environment,
		},
		&cli.StringFlag{
			Name:        "secret-file",
			Aliases:     []string{"S"},
			Value:       defEmptyValue,
			Usage:       "Use `FILE` as the local osquery enrollment secret file. Default depends on OS",
			EnvVars:     []string{"OSQUERY_SECRET"},
			Destination: &appConfig.OsquerySecretFile,
		},
		&cli.StringFlag{
			Name:        "flagfile",
			Aliases:     []string{"F"},
			Value:       defEmptyValue,
			Usage:       "Use `FILE` as the local osquery flags file. Default depends on OS",
			EnvVars:     []string{"OSQUERY_FLAGFILE"},
			Destination: &appConfig.OsqueryFlagFile,
		},
		&cli.StringFlag{
			Name:        "certificate",
			Aliases:     []string{"C"},
			Value:       defEmptyValue,
			Usage:       "Use `FILE` as the local osquery TLS certificate file, if needed. Default depends on OS",
			EnvVars:     []string{"OSQUERY_CERTIFICATE"},
			Destination: &appConfig.OsqueryCertFile,
		},
		&cli.StringFlag{
			Name:        "osctrl-url",
			Aliases:     []string{"U"},
			Value:       defEmptyValue,
			Usage:       "Base URL for the osctrl server",
			EnvVars:     []string{"OSCTRL_URL"},
			Destination: &appConfig.BaseURL,
		},
		&cli.StringFlag{
			Name:        "osquery-path",
			Aliases:     []string{"osquery", "o"},
			Value:       defEmptyValue,
			Usage:       "Use `FILE` as path for osquery installation, if needed. Default depends on OS",
			EnvVars:     []string{"OSQUERY_PATH"},
			Destination: &appConfig.OsqueryPath,
		},
		&cli.BoolFlag{
			Name:        "insecure",
			Aliases:     []string{"i"},
			Value:       false,
			Usage:       "Ignore TLS warnings, often used with self-signed certificates",
			EnvVars:     []string{"OSCTRL_INSECURE"},
			Destination: &appConfig.Insecure,
		},
		&cli.BoolFlag{
			Name:        "verbose",
			Aliases:     []string{"V"},
			Value:       false,
			Usage:       "Enable verbose informational messages",
			EnvVars:     []string{"OSCTRL_VERBOSE"},
			Destination: &appConfig.Verbose,
		},
		&cli.BoolFlag{
			Name:        "force",
			Aliases:     []string{"f"},
			Value:       false,
			Usage:       "Overwrite existing files for flags, certificate and secret",
			EnvVars:     []string{"OSCTRL_FORCE"},
			Destination: &appConfig.Force,
		},
		&cli.StringFlag{
			Name:        "log-format",
			Aliases:     []string{"L"},
			Value:       defLogFormat,
			Usage:       "Log output format: text or json",
			EnvVars:     []string{"OSCTRL_LOG_FORMAT"},
			Destination: &appConfig.LogFormat,
		},
		&cli.IntFlag{
			Name:        "interval",
			Aliases:     []string{"I"},
			Value:       defInterval,
			Usage:       "Sync interval in minutes for service mode",
			EnvVars:     []string{"OSCTRL_INTERVAL"},
			Destination: &appConfig.Interval,
		},
	}
}

func defaultConfigurationYAML() (string, error) {
	var out bytes.Buffer
	encoder := yaml.NewEncoder(&out)
	encoder.SetIndent(2)
	if err := encoder.Encode(ConfigurationFile{Osctrld: defaultConfiguration()}); err != nil {
		return "", fmt.Errorf("error encoding default configuration: %v", err)
	}
	if err := encoder.Close(); err != nil {
		return "", fmt.Errorf("error closing default configuration encoder: %v", err)
	}
	return out.String(), nil
}

func applyConfigurationDefaults(cfg *Configuration) {
	switch runtime.GOOS {
	case DarwinOS:
		applyOsqueryPathDefaults(cfg, defDarwinPath, shExtension)
	case LinuxOS:
		applyOsqueryPathDefaults(cfg, defLinuxPath, shExtension)
	case WindowsOS:
		applyOsqueryPathDefaults(cfg, defWindowsPath, ps1Extension)
	}
	if cfg.LogFormat == "" {
		cfg.LogFormat = defLogFormat
	}
	if cfg.Interval == 0 {
		cfg.Interval = defInterval
	}
}

func applyOsqueryPathDefaults(cfg *Configuration, defaultPath, scriptExtension string) {
	if cfg.OsqueryPath == defEmptyValue {
		cfg.OsqueryPath = defaultPath
	}
	if cfg.OsqueryFlagFile == defEmptyValue {
		cfg.OsqueryFlagFile = genFullPath(cfg.OsqueryPath, defFlagFile)
	}
	if cfg.OsquerySecretFile == defEmptyValue {
		cfg.OsquerySecretFile = genFullPath(cfg.OsqueryPath, defSecretFile)
	}
	if cfg.OsqueryCertFile == defEmptyValue {
		cfg.OsqueryCertFile = genFullPath(cfg.OsqueryPath, defCertificate)
	}
	if cfg.EnrollScript == "" {
		cfg.EnrollScript = genFullPath(cfg.OsqueryPath, defEnrollScript+scriptExtension)
	}
	if cfg.RemoveScript == "" {
		cfg.RemoveScript = genFullPath(cfg.OsqueryPath, defRemoveScript+scriptExtension)
	}
	if cfg.ExtensionsDir == "" {
		cfg.ExtensionsDir = genFullPath(cfg.OsqueryPath, "extensions/")
	}
}

func validateConfiguration(cfg Configuration) error {
	var problems []string
	if cfg.OsctrlSecret == defEmptyValue {
		problems = append(problems, "osctrlSecret is required")
	}
	if cfg.Environment == defEmptyValue {
		problems = append(problems, "environment is required")
	}
	if cfg.BaseURL == defEmptyValue {
		problems = append(problems, "baseurl is required")
	} else if parsed, err := url.Parse(cfg.BaseURL); err != nil || parsed.Host == "" {
		problems = append(problems, "baseurl must be a valid URL")
	} else if parsed.Scheme != "http" && parsed.Scheme != "https" {
		problems = append(problems, "baseurl must use http or https")
	}
	if cfg.LogFormat != defLogFormat && cfg.LogFormat != "json" {
		problems = append(problems, "logFormat must be text or json")
	}
	if cfg.Interval <= 0 {
		problems = append(problems, "interval must be greater than 0")
	}
	if len(problems) > 0 {
		return fmt.Errorf("invalid configuration: %s", strings.Join(problems, "; "))
	}
	return nil
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
	applyLegacyConfigurationFields(configRaw, &cfg)
	return cfg, nil
}

func applyLegacyConfigurationFields(configRaw *viper.Viper, cfg *Configuration) {
	if cfg.OsctrlSecret == "" {
		cfg.OsctrlSecret = configRaw.GetString("secret")
	}
	if cfg.OsquerySecretFile == "" {
		cfg.OsquerySecretFile = configRaw.GetString("secretFile")
	}
	if cfg.OsqueryFlagFile == "" {
		cfg.OsqueryFlagFile = configRaw.GetString("flags")
	}
	if cfg.OsqueryCertFile == "" {
		cfg.OsqueryCertFile = configRaw.GetString("cert")
	}
}
