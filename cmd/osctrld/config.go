package main

import (
	"bytes"
	"fmt"
	"math"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"runtime"
	"slices"
	"strings"
	"time"

	"github.com/rs/zerolog/log"
	"github.com/spf13/viper"
	"github.com/urfave/cli/v3"
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
	// Longest sync interval in minutes: the service waits interval*time.Minute
	// plus up to 10% jitter, which must not overflow int64 (about 266 years)
	maxInterval = math.MaxInt64 / int64(time.Minute) * 10 / 11
	// Sync intervals above one week are accepted but warned about
	longInterval = 7 * 24 * 60
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
	OsquerySHA256     string `json:"osquerySHA256" yaml:"osquerySHA256" mapstructure:"osquerySHA256"`
	OsqueryPackage    string `json:"osqueryPackage" yaml:"osqueryPackage" mapstructure:"osqueryPackage"`
	AllowUnverified   bool   `json:"allowUnverified" yaml:"allowUnverified" mapstructure:"allowUnverified"`
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
		Environment:       "osctrl_environment_UUID",
		BaseURL:           "https://osctrl.url",
		Insecure:          false,
		Verbose:           false,
		Force:             false,
		LogFormat:         defLogFormat,
		Interval:          defInterval,
		ExtensionsDir:     "/path/to/extensions/",
		OsquerySHA256:     "sha256-of-the-osquery-package",
		OsqueryPackage:    "",
		AllowUnverified:   false,
	}
}

func buildConfigFlags() []cli.Flag {
	return []cli.Flag{
		&cli.StringFlag{
			Name:        "configuration",
			Aliases:     []string{"c", "conf", "config"},
			Value:       defEmptyValue,
			Usage:       "Configuration file for osctrld to load all necessary values",
			Sources:     cli.EnvVars("OSCTRL_CONFIG"),
			Destination: &configFile,
		},
		&cli.StringFlag{
			Name:        "secret",
			Aliases:     []string{"s"},
			Value:       defEmptyValue,
			Usage:       "osctrl enrollment secret used to authenticate with the osctrl server; prefer OSCTRL_SECRET or a config file, arguments are visible in the process list",
			Sources:     cli.EnvVars("OSCTRL_SECRET"),
			Destination: &appConfig.OsctrlSecret,
		},
		&cli.StringFlag{
			Name:        "environment",
			Aliases:     []string{"e", "env"},
			Value:       defEmptyValue,
			Usage:       "UUID of the osctrl environment to enroll nodes in",
			Sources:     cli.EnvVars("OSCTRL_ENV"),
			Destination: &appConfig.Environment,
		},
		&cli.StringFlag{
			Name:        "secret-file",
			Aliases:     []string{"S"},
			Value:       defEmptyValue,
			Usage:       "Use `FILE` as the local osquery enrollment secret file. Default depends on OS",
			Sources:     cli.EnvVars("OSQUERY_SECRET"),
			Destination: &appConfig.OsquerySecretFile,
		},
		&cli.StringFlag{
			Name:        "flagfile",
			Aliases:     []string{"F"},
			Value:       defEmptyValue,
			Usage:       "Use `FILE` as the local osquery flags file. Default depends on OS",
			Sources:     cli.EnvVars("OSQUERY_FLAGFILE"),
			Destination: &appConfig.OsqueryFlagFile,
		},
		&cli.StringFlag{
			Name:        "certificate",
			Aliases:     []string{"C"},
			Value:       defEmptyValue,
			Usage:       "Use `FILE` as the local osquery TLS certificate file, if needed. Default depends on OS",
			Sources:     cli.EnvVars("OSQUERY_CERTIFICATE"),
			Destination: &appConfig.OsqueryCertFile,
		},
		&cli.StringFlag{
			Name:        "osctrl-url",
			Aliases:     []string{"U"},
			Value:       defEmptyValue,
			Usage:       "Base URL for the osctrl server",
			Sources:     cli.EnvVars("OSCTRL_URL"),
			Destination: &appConfig.BaseURL,
		},
		&cli.StringFlag{
			Name:        "osquery-path",
			Aliases:     []string{"osquery", "o"},
			Value:       defEmptyValue,
			Usage:       "Use `FILE` as path for osquery installation, if needed. Default depends on OS",
			Sources:     cli.EnvVars("OSQUERY_PATH"),
			Destination: &appConfig.OsqueryPath,
		},
		&cli.BoolFlag{
			Name:        "insecure",
			Aliases:     []string{"i"},
			Value:       false,
			Usage:       "Ignore TLS warnings, often used with self-signed certificates",
			Sources:     cli.EnvVars("OSCTRL_INSECURE"),
			Destination: &appConfig.Insecure,
		},
		&cli.BoolFlag{
			Name:        "verbose",
			Aliases:     []string{"V"},
			Value:       false,
			Usage:       "Enable verbose informational messages",
			Sources:     cli.EnvVars("OSCTRL_VERBOSE"),
			Destination: &appConfig.Verbose,
		},
		&cli.BoolFlag{
			Name:        "force",
			Aliases:     []string{"f"},
			Value:       false,
			Usage:       "Overwrite existing files for flags, certificate and secret",
			Sources:     cli.EnvVars("OSCTRL_FORCE"),
			Destination: &appConfig.Force,
		},
		&cli.StringFlag{
			Name:        "log-format",
			Aliases:     []string{"L"},
			Value:       defLogFormat,
			Usage:       "Log output format: text or json",
			Sources:     cli.EnvVars("OSCTRL_LOG_FORMAT"),
			Destination: &appConfig.LogFormat,
		},
		&cli.IntFlag{
			Name:        "interval",
			Aliases:     []string{"I"},
			Value:       defInterval,
			Usage:       "Sync interval in minutes for service mode",
			Sources:     cli.EnvVars("OSCTRL_INTERVAL"),
			Destination: &appConfig.Interval,
		},
		&cli.StringFlag{
			Name:        "osquery-sha256",
			Aliases:     []string{"H"},
			Value:       defEmptyValue,
			Usage:       "Expected SHA-256 of the osquery package, used by the install command",
			Sources:     cli.EnvVars("OSQUERY_SHA256"),
			Destination: &appConfig.OsquerySHA256,
		},
		&cli.StringFlag{
			Name:        "osquery-package",
			Aliases:     []string{"P"},
			Value:       defEmptyValue,
			Usage:       "Override the osquery package URL, for mirrors and air-gapped installs",
			Sources:     cli.EnvVars("OSQUERY_PACKAGE"),
			Destination: &appConfig.OsqueryPackage,
		},
		&cli.BoolFlag{
			Name:        "allow-unverified",
			Value:       false,
			Usage:       "Install the osquery package even when no SHA-256 is available to verify it",
			Sources:     cli.EnvVars("OSCTRL_ALLOW_UNVERIFIED"),
			Destination: &appConfig.AllowUnverified,
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
	// A trailing slash makes "//<env>/..." URLs, which osctrl redirects as GET
	cfg.BaseURL = strings.TrimRight(cfg.BaseURL, "/")
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

// envUUIDPattern is the only environment form osctrl's osctrld endpoints accept;
// they look the environment up by UUID and answer HTTP 400 to anything else
var envUUIDPattern = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

func validateConfiguration(cfg Configuration) error {
	var problems []string
	if cfg.OsctrlSecret == defEmptyValue {
		problems = append(problems, "osctrlSecret is required")
	}
	if cfg.Environment == defEmptyValue {
		problems = append(problems, "environment is required")
	} else if !envUUIDPattern.MatchString(cfg.Environment) {
		problems = append(problems, "environment must be the osctrl environment UUID, not its name")
	}
	if cfg.BaseURL == defEmptyValue {
		problems = append(problems, "baseurl is required")
	} else if parsed, err := url.Parse(cfg.BaseURL); err != nil || parsed.Host == "" {
		problems = append(problems, "baseurl must be a valid URL")
	} else if parsed.Scheme != "http" && parsed.Scheme != "https" {
		problems = append(problems, "baseurl must use http or https")
	} else if strings.ContainsAny(cfg.BaseURL, "?#") {
		// genURLs appends "/<env>/..." which would end up inside them
		problems = append(problems, "baseurl must not contain a query or fragment")
	}
	if cfg.LogFormat != defLogFormat && cfg.LogFormat != "json" {
		problems = append(problems, "logFormat must be text or json")
	}
	if cfg.Interval <= 0 {
		problems = append(problems, "interval must be greater than 0")
	} else if int64(cfg.Interval) > maxInterval {
		problems = append(problems, fmt.Sprintf("interval is too large, the maximum is %d minutes", maxInterval))
	}
	if len(problems) > 0 {
		return fmt.Errorf("invalid configuration: %s", strings.Join(problems, "; "))
	}
	return nil
}

// loadConfiguration reads the osctrld section of file. It also returns the
// names of keys it does not know, so a typo can be warned about.
func loadConfiguration(file string, verbose bool) (Configuration, []string, error) {
	var cfg Configuration
	log.Debug().Str("path", file).Msg("loading configuration")
	viper.SetConfigFile(file)
	if err := viper.ReadInConfig(); err != nil {
		return cfg, nil, err
	}
	configRaw := viper.Sub(configurationKey)
	if configRaw == nil {
		return cfg, nil, fmt.Errorf("configuration file has no %q section; all settings go under it, see default-config", configurationKey)
	}
	if err := configRaw.Unmarshal(&cfg); err != nil {
		return cfg, nil, err
	}
	applyLegacyConfigurationFields(configRaw, &cfg)
	return cfg, unknownConfigurationKeys(configRaw), nil
}

// legacyConfigurationKeys are read by applyLegacyConfigurationFields
var legacyConfigurationKeys = []string{"secret", "secretFile", "flags", "cert"}

// unknownConfigurationKeys lists the top-level keys that match no Configuration
// field or legacy key, ignoring case like viper does
func unknownConfigurationKeys(configRaw *viper.Viper) []string {
	known := map[string]bool{}
	for _, k := range legacyConfigurationKeys {
		known[strings.ToLower(k)] = true
	}
	t := reflect.TypeFor[Configuration]()
	for i := range t.NumField() {
		known[strings.ToLower(t.Field(i).Tag.Get("mapstructure"))] = true
	}
	var unknown []string
	for _, k := range configRaw.AllKeys() {
		top, _, _ := strings.Cut(k, ".")
		if !known[top] && !slices.Contains(unknown, top) {
			unknown = append(unknown, top)
		}
	}
	slices.Sort(unknown)
	return unknown
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

// ignoredByConfigFile names the flags and environment variables set for this
// run, all of which a configuration file overrides. Names only: values may be
// secrets. An environment variable is named instead of its flag when set.
func ignoredByConfigFile() []string {
	var ignored []string
	for _, f := range flags {
		name := f.Names()[0]
		if name == "configuration" || !f.IsSet() {
			continue
		}
		fromEnv := false
		if ef, ok := f.(interface{ GetEnvVars() []string }); ok {
			for _, env := range ef.GetEnvVars() {
				if _, set := os.LookupEnv(env); set {
					ignored = append(ignored, env)
					fromEnv = true
				}
			}
		}
		if !fromEnv {
			ignored = append(ignored, "--"+name)
		}
	}
	return ignored
}

// warnRelativePaths warns about path options that resolve against the working
// directory, which is / for a service under systemd or launchd
func warnRelativePaths(cfg Configuration) {
	var relative []string
	for _, p := range []struct{ option, path string }{
		{"osquery", cfg.OsqueryPath},
		{"osquerySecretFile", cfg.OsquerySecretFile},
		{"osqueryFlagFile", cfg.OsqueryFlagFile},
		{"osqueryCertFile", cfg.OsqueryCertFile},
		{"enrollScript", cfg.EnrollScript},
		{"removeScript", cfg.RemoveScript},
		{"extensionsDir", cfg.ExtensionsDir},
	} {
		if p.path != defEmptyValue && !filepath.IsAbs(p.path) {
			relative = append(relative, p.option)
		}
	}
	if len(relative) > 0 {
		log.Warn().Strs("options", relative).Msg("relative paths resolve against the working directory, which is / under systemd and launchd; use absolute paths")
	}
}

// warnUnusualValues warns about accepted values that are likely mistakes or
// discouraged; never with the values, which may hold credentials
func warnUnusualValues(cfg Configuration) {
	if u, err := url.Parse(cfg.BaseURL); err == nil && u.User != nil {
		log.Warn().Str("option", "baseurl").Msg("credentials in baseurl are discouraged: they are sent as Basic auth and stored in the configuration")
	}
	if cfg.Interval > longInterval {
		log.Warn().Int("interval_minutes", cfg.Interval).Msgf("interval is unusually long, more than one week (%d minutes)", longInterval)
	}
}

// redactURL keeps only scheme, host and path, dropping userinfo, query and
// fragment, which may carry credentials
func redactURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return "[unparseable]"
	}
	return (&url.URL{Scheme: u.Scheme, Host: u.Host, Path: u.Path}).String()
}

// warnCleartextURLs warns once per start about options that send data over
// plain http. http stays accepted so existing fleets keep working.
func warnCleartextURLs(cfg Configuration) {
	risks := []struct{ option, value, risk string }{
		{"baseurl", cfg.BaseURL, "the enrollment secret, flags, certificate and extensions with their SHA-256 travel unencrypted and can be read or replaced on the network"},
		{"osqueryPackage", cfg.OsqueryPackage, "the osquery package downloads unencrypted; only its SHA-256 check protects it"},
	}
	for _, r := range risks {
		if u, err := url.Parse(r.value); err == nil && u.Scheme == "http" {
			log.Warn().Str("option", r.option).Str("url", u.Scheme+"://"+u.Host).Msg("plain http is insecure, use https: " + r.risk)
		}
	}
}
