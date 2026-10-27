package main

import (
	"bytes"
	"context"
	"math"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/urfave/cli/v3"
)

func TestLoadConfigurationInvalid(t *testing.T) {
	_, _, err := loadConfiguration("nonexistent-file.yaml", false)
	assert.Error(t, err)
}

func TestLoadConfigurationJSON(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "osctrld-test.json")
	configData := []byte(`{
  "osctrld": {
    "osctrlSecret": "test-secret",
    "osquerySecretFile": "/tmp/osquery.secret",
    "osqueryFlagFile": "/tmp/osquery.flags",
    "osqueryCertFile": "/tmp/osctrl.crt",
    "environment": "dev",
    "baseurl": "https://localhost:9000",
    "insecure": true,
    "verbose": true,
    "force": true
  }
}`)
	err := os.WriteFile(configPath, configData, 0644)
	assert.NoError(t, err)

	cfg, _, err := loadConfiguration(configPath, false)
	assert.NoError(t, err)
	assert.Equal(t, "test-secret", cfg.OsctrlSecret)
	assert.Equal(t, "/tmp/osquery.secret", cfg.OsquerySecretFile)
	assert.Equal(t, "/tmp/osquery.flags", cfg.OsqueryFlagFile)
	assert.Equal(t, "/tmp/osctrl.crt", cfg.OsqueryCertFile)
	assert.Equal(t, "dev", cfg.Environment)
	assert.Equal(t, "https://localhost:9000", cfg.BaseURL)
	assert.True(t, cfg.Insecure)
	assert.True(t, cfg.Verbose)
	assert.True(t, cfg.Force)
}

func TestLoadConfigurationYAML(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "osctrld-test.yaml")
	configData := []byte(`osctrld:
  osctrlSecret: "test-secret"
  osquerySecretFile: "/tmp/osquery.secret"
  osqueryFlagFile: "/tmp/osquery.flags"
  osqueryCertFile: "/tmp/osctrl.crt"
  environment: "dev"
  baseurl: "https://localhost:9000"
  insecure: true
  verbose: true
  force: true
  logFormat: "json"
  interval: 30
  extensionsDir: "/tmp/extensions/"
`)
	err := os.WriteFile(configPath, configData, 0644)
	assert.NoError(t, err)

	cfg, _, err := loadConfiguration(configPath, false)
	assert.NoError(t, err)
	assert.Equal(t, "test-secret", cfg.OsctrlSecret)
	assert.Equal(t, "/tmp/osquery.secret", cfg.OsquerySecretFile)
	assert.Equal(t, "/tmp/osquery.flags", cfg.OsqueryFlagFile)
	assert.Equal(t, "/tmp/osctrl.crt", cfg.OsqueryCertFile)
	assert.Equal(t, "dev", cfg.Environment)
	assert.Equal(t, "https://localhost:9000", cfg.BaseURL)
	assert.True(t, cfg.Insecure)
	assert.True(t, cfg.Verbose)
	assert.True(t, cfg.Force)
	assert.Equal(t, "json", cfg.LogFormat)
	assert.Equal(t, 30, cfg.Interval)
	assert.Equal(t, "/tmp/extensions/", cfg.ExtensionsDir)
}

func TestLoadConfigurationLegacySecretFields(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "osctrld-legacy.yaml")
	configData := []byte(`osctrld:
  secret: "legacy-secret"
  secretFile: "/tmp/legacy.secret"
  flags: "/tmp/legacy.flags"
  cert: "/tmp/legacy.crt"
`)
	err := os.WriteFile(configPath, configData, 0644)
	assert.NoError(t, err)

	cfg, _, err := loadConfiguration(configPath, false)
	assert.NoError(t, err)
	assert.Equal(t, "legacy-secret", cfg.OsctrlSecret)
	assert.Equal(t, "/tmp/legacy.secret", cfg.OsquerySecretFile)
	assert.Equal(t, "/tmp/legacy.flags", cfg.OsqueryFlagFile)
	assert.Equal(t, "/tmp/legacy.crt", cfg.OsqueryCertFile)
}

func TestBuildConfigFlagsIncludesConfigurationDefaults(t *testing.T) {
	appConfig = Configuration{}
	configFile = defEmptyValue

	configFlags := buildConfigFlags()

	assert.Len(t, configFlags, 16)
	assert.Equal(t, "configuration", configFlags[0].Names()[0])
	assert.Equal(t, "secret", configFlags[1].Names()[0])
	logFormatFlag, ok := configFlags[11].(*cli.StringFlag)
	assert.True(t, ok)
	assert.Equal(t, defLogFormat, logFormatFlag.Value)
	intervalFlag, ok := configFlags[12].(*cli.IntFlag)
	assert.True(t, ok)
	assert.Equal(t, defInterval, intervalFlag.Value)
}

func TestValidateConfigurationAcceptsValidConfig(t *testing.T) {
	cfg := Configuration{
		OsctrlSecret: "test-secret",
		Environment:  "11111111-1111-4111-8111-111111111111",
		BaseURL:      "https://localhost:9000",
		LogFormat:    "json",
		Interval:     30,
	}
	applyConfigurationDefaults(&cfg)

	assert.NoError(t, validateConfiguration(cfg))
	assert.NotEmpty(t, cfg.OsquerySecretFile)
	assert.NotEmpty(t, cfg.OsqueryFlagFile)
	assert.NotEmpty(t, cfg.OsqueryCertFile)
}

func TestValidateConfigurationRejectsMissingRequiredFields(t *testing.T) {
	cfg := Configuration{
		LogFormat: defLogFormat,
		Interval:  defInterval,
	}

	err := validateConfiguration(cfg)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "osctrlSecret is required")
	assert.Contains(t, err.Error(), "environment is required")
	assert.Contains(t, err.Error(), "baseurl is required")
}

func TestValidateConfigurationRejectsInvalidValues(t *testing.T) {
	cfg := Configuration{
		OsctrlSecret: "test-secret",
		Environment:  "11111111-1111-4111-8111-111111111111",
		BaseURL:      "ftp://localhost",
		LogFormat:    "xml",
		Interval:     0,
	}

	err := validateConfiguration(cfg)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "baseurl must use http or https")
	assert.Contains(t, err.Error(), "logFormat must be text or json")
	assert.Contains(t, err.Error(), "interval must be greater than 0")
}

func TestBuildConfigFlagsIncludesInstallFlags(t *testing.T) {
	configFlags := buildConfigFlags()

	names := map[string]bool{}
	for _, f := range configFlags {
		names[f.Names()[0]] = true
	}
	assert.True(t, names["osquery-sha256"], "osquery-sha256 flag missing")
	assert.True(t, names["allow-unverified"], "allow-unverified flag missing")
	assert.True(t, names["osquery-package"], "osquery-package flag missing")
}

func TestCheckConfigCommandValidatesConfigurationFile(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "osctrld.yaml")
	configData := []byte(`osctrld:
  osctrlSecret: "test-secret"
  environment: "11111111-1111-4111-8111-111111111111"
  baseurl: "https://localhost:9000"
  logFormat: "text"
  interval: 60
`)
	assert.NoError(t, os.WriteFile(configPath, configData, 0644))

	appConfig = Configuration{}
	configFile = defEmptyValue
	app := buildApp()
	var output strings.Builder
	app.Writer = &output

	err := app.Run(context.Background(), []string{"osctrld", "--configuration", configPath, "check-config"})

	assert.NoError(t, err)
	assert.Contains(t, output.String(), "configuration is valid")
}

// osctrl's osctrld endpoints look the environment up by UUID and answer a bare
// HTTP 400 to anything else, so a name must be caught here with a clear message.
func TestValidateConfigurationRequiresEnvironmentUUID(t *testing.T) {
	cases := []struct {
		name  string
		env   string
		valid bool
	}{
		{"canonical uuid", "11111111-1111-4111-8111-111111111111", true},
		{"uppercase uuid", "A1B2C3D4-E5F6-4A7B-8C9D-0E1F2A3B4C5D", true},
		{"environment name", "dev", false},
		{"uuid without dashes", "11111111111141118111111111111111", false},
		{"uuid with trailing text", "11111111-1111-4111-8111-111111111111x", false},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			cfg := Configuration{OsctrlSecret: "s", Environment: tt.env, BaseURL: "https://osctrl.example", LogFormat: defLogFormat, Interval: defInterval}
			err := validateConfiguration(cfg)
			if tt.valid {
				assert.NoError(t, err)
				return
			}
			require.Error(t, err)
			assert.Contains(t, err.Error(), "environment must be the osctrl environment UUID")
		})
	}
}

func TestWarnCleartextURLs(t *testing.T) {
	tests := []struct {
		name, baseURL, pkg string
		want               []string
	}{
		{"https everywhere", "https://osctrl.example.com", "https://mirror.example.com/osquery.pkg", nil},
		{"no package override", "https://osctrl.example.com", "", nil},
		{"http baseurl", "http://osctrl.example.com", "", []string{"baseurl"}},
		{"http package", "https://osctrl.example.com", "http://mirror.example.com/osquery.pkg", []string{"osqueryPackage"}},
		{"both http", "HTTP://osctrl.example.com", "http://mirror.example.com/osquery.pkg", []string{"baseurl", "osqueryPackage"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var logs bytes.Buffer
			old := log.Logger
			log.Logger = zerolog.New(&logs)
			t.Cleanup(func() { log.Logger = old })
			warnCleartextURLs(Configuration{BaseURL: tt.baseURL, OsqueryPackage: tt.pkg})
			out := logs.String()
			if tt.want == nil {
				assert.Empty(t, out)
				return
			}
			assert.Equal(t, len(tt.want), strings.Count(out, `"level":"warn"`))
			for _, opt := range tt.want {
				assert.Contains(t, out, `"option":"`+opt+`"`)
			}
		})
	}
}

// writeConfig writes content to a config file named name in a temp dir
func writeConfig(t *testing.T, name, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	require.NoError(t, os.WriteFile(path, []byte(content), 0600))
	return path
}

// A file without the osctrld section used to panic on a nil viper.Sub
func TestLoadConfigurationWithoutOsctrldSection(t *testing.T) {
	for name, content := range map[string]string{
		"other key":    "something:\n  baseurl: https://osctrl.example\n",
		"scalar value": "osctrld: nope\n",
		"empty file":   "",
	} {
		t.Run(name, func(t *testing.T) {
			_, _, err := loadConfiguration(writeConfig(t, "osctrld.yaml", content), false)
			require.Error(t, err)
			assert.Contains(t, err.Error(), `"osctrld" section`)
		})
	}
}

// syncInterval multiplies by time.Minute and the service adds up to 10% jitter:
// an interval where that overflows int64 became a negative or tiny duration and
// a tight sync loop, so only those values are refused
func TestValidateConfigurationIntervalBounds(t *testing.T) {
	for _, tt := range []struct {
		interval int
		want     string
	}{
		{1, ""},
		{defInterval, ""},
		{longInterval + 1, ""},
		{int(maxInterval), ""},
		{int(maxInterval) + 1, "interval is too large"},
		{999999999999, "interval is too large"},
		{math.MaxInt, "interval is too large"},
		{0, "interval must be greater than 0"},
		{-1, "interval must be greater than 0"},
		{math.MinInt, "interval must be greater than 0"},
	} {
		t.Run(strconv.Itoa(tt.interval), func(t *testing.T) {
			cfg := Configuration{OsctrlSecret: "s", Environment: "11111111-1111-4111-8111-111111111111", BaseURL: "https://osctrl.example", LogFormat: defLogFormat, Interval: tt.interval}
			err := validateConfiguration(cfg)
			if tt.want == "" {
				assert.NoError(t, err)
				return
			}
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.want)
		})
	}
}

// The largest accepted interval never overflows into a short wait, jitter included
func TestMaxIntervalDoesNotOverflow(t *testing.T) {
	base := time.Duration(maxInterval) * time.Minute
	require.Positive(t, base)
	for range 1000 {
		require.Greater(t, intervalWithJitter(base), base*8/10)
	}
}

// genURLs appends "/<env>/..." to baseurl: a query or fragment swallows that
// path, so requests go to "/" and fail. Userinfo works (Basic auth) and is accepted
func TestValidateConfigurationBaseURLParts(t *testing.T) {
	for _, tt := range []struct {
		name, url, want string
	}{
		{"plain", "https://osctrl.example", ""},
		{"with path", "https://osctrl.example/osctrl", ""},
		{"with port", "https://osctrl.example:8443", ""},
		{"userinfo is accepted, it works as Basic auth", "https://user:pass@osctrl.example", ""},
		{"username only", "https://user@osctrl.example", ""},
		{"query", "https://osctrl.example?a=b", "baseurl must not contain a query or fragment"},
		{"empty query", "https://osctrl.example?", "baseurl must not contain a query or fragment"},
		{"fragment", "https://osctrl.example#x", "baseurl must not contain a query or fragment"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			cfg := Configuration{OsctrlSecret: "s", Environment: "11111111-1111-4111-8111-111111111111", BaseURL: tt.url, LogFormat: defLogFormat, Interval: defInterval}
			err := validateConfiguration(cfg)
			if tt.want == "" {
				assert.NoError(t, err)
				return
			}
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.want)
			assert.NotContains(t, err.Error(), "pass", "the error must not echo the credential")
		})
	}
}

// A trailing slash made "//<env>/..." URLs, which osctrl answers with a 301
// that turns the POST into a GET
func TestApplyConfigurationDefaultsTrimsBaseURLSlash(t *testing.T) {
	for in, want := range map[string]string{
		"https://osctrl.example/":        "https://osctrl.example",
		"https://osctrl.example//":       "https://osctrl.example",
		"https://osctrl.example/osctrl/": "https://osctrl.example/osctrl",
		"https://osctrl.example":         "https://osctrl.example",
	} {
		cfg := Configuration{BaseURL: in}
		applyConfigurationDefaults(&cfg)
		assert.Equal(t, want, cfg.BaseURL, in)
		assert.Equal(t, want+"/env/osctrld-flags", genURLs(cfg.BaseURL, "env", false).Flags)
	}
}

// The debug "configuration loaded" line must never print the secret or URL userinfo
func TestLogLoadedConfigurationRedacts(t *testing.T) {
	var logs bytes.Buffer
	old := log.Logger
	oldLevel := zerolog.GlobalLevel()
	log.Logger = zerolog.New(&logs)
	zerolog.SetGlobalLevel(zerolog.DebugLevel)
	t.Cleanup(func() { log.Logger = old; zerolog.SetGlobalLevel(oldLevel) })
	logLoadedConfiguration(Configuration{
		OsctrlSecret:   "s3cr3t-value",
		BaseURL:        "https://user:hunter2@osctrl.example/base?token=t0k3n#frag",
		OsqueryPackage: "https://u:p4ss@mirror.example/osquery.pkg?sig=abc",
		Environment:    "11111111-1111-4111-8111-111111111111",
	}, "service")
	out := logs.String()
	assert.Contains(t, out, "configuration loaded")
	assert.Contains(t, out, "https://osctrl.example/base")
	assert.Contains(t, out, "https://mirror.example/osquery.pkg")
	for _, secret := range []string{"s3cr3t-value", "user", "hunter2", "t0k3n", "frag", "p4ss", "sig=abc"} {
		assert.NotContains(t, out, secret)
	}
}

// A misspelled key used to be dropped silently; it is warned about (names only),
// while the legacy keys older configs and packages still use are not
func TestLoadConfigurationUnknownKeys(t *testing.T) {
	for _, tt := range []struct {
		name, content string
		want          []string
	}{
		{"valid", "osctrld:\n  osctrlSecret: s\n  baseurl: https://osctrl.example\n  interval: 5\n  osquery: /etc/osquery/\n  allowUnverified: true\n", nil},
		{"legacy keys", "osctrld:\n  secret: s\n  secretFile: /a\n  flags: /b\n  cert: /c\n", nil},
		{"typos", "osctrld:\n  insecrue: true\n  osctrlSecret: s\n  baseURL: https://osctrl.example\n  secrett: hunter2\n", []string{"insecrue", "secrett"}},
		{"nested unknown", "osctrld:\n  proxy:\n    url: http://p\n", []string{"proxy"}},
		{"json typo", `{"osctrld": {"osctrlSecret": "s", "intervall": 5}}`, []string{"intervall"}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			ext := ".yaml"
			if strings.HasPrefix(tt.content, "{") {
				ext = ".json"
			}
			_, unknown, err := loadConfiguration(writeConfig(t, "osctrld"+ext, tt.content), false)
			require.NoError(t, err)
			assert.Equal(t, tt.want, unknown)
			assert.NotContains(t, strings.Join(unknown, ","), "hunter2")
		})
	}
}

// configurationKeys lists the file keys of Configuration, from its tags
func configurationKeys() []string {
	var keys []string
	t := reflect.TypeFor[Configuration]()
	for i := range t.NumField() {
		keys = append(keys, t.Field(i).Tag.Get("mapstructure"))
	}
	slices.Sort(keys)
	return keys
}

// The sample is installed by the packages as /etc/osctrld/osctrld.yaml: an
// unedited copy must leave every path to the OS defaults (its old /path/to
// placeholders made root create /path/to/extensions), and only fail validation
// on the environment placeholder, so it can never sync against a wrong UUID
func TestSampleConfiguration(t *testing.T) {
	cfg, unknown, err := loadConfiguration(filepath.Join("..", "..", "service", "osctrld-sample.yaml"), false)
	require.NoError(t, err)
	assert.Empty(t, unknown)
	want := Configuration{OsctrlSecret: cfg.OsctrlSecret, Environment: cfg.Environment, BaseURL: cfg.BaseURL, LogFormat: cfg.LogFormat, Interval: cfg.Interval}
	applyConfigurationDefaults(&want)
	applyConfigurationDefaults(&cfg)
	assert.Equal(t, want.OsqueryPath, cfg.OsqueryPath)
	assert.Equal(t, want.OsqueryFlagFile, cfg.OsqueryFlagFile)
	assert.Equal(t, want.OsquerySecretFile, cfg.OsquerySecretFile)
	assert.Equal(t, want.OsqueryCertFile, cfg.OsqueryCertFile)
	assert.Equal(t, want.EnrollScript, cfg.EnrollScript)
	assert.Equal(t, want.RemoveScript, cfg.RemoveScript)
	assert.Equal(t, want.ExtensionsDir, cfg.ExtensionsDir)
	assert.False(t, cfg.Insecure)
	assert.False(t, cfg.AllowUnverified)
	assert.Empty(t, cfg.OsquerySHA256, "a placeholder digest would make install fail")

	err = validateConfiguration(cfg)
	require.Error(t, err)
	assert.Equal(t, "invalid configuration: environment must be the osctrl environment UUID, not its name", err.Error())
	cfg.Environment = "11111111-1111-4111-8111-111111111111"
	assert.NoError(t, validateConfiguration(cfg))
}

// Every Configuration key appears in the sample (set or as a commented
// example), in the README table, and in default-config
func TestConfigurationKeysDocumented(t *testing.T) {
	keyLine := regexp.MustCompile(`(?m)^\s*#?\s*([A-Za-z0-9]+):`)
	sample, err := os.ReadFile(filepath.Join("..", "..", "service", "osctrld-sample.yaml"))
	require.NoError(t, err)
	defaults, err := defaultConfigurationYAML()
	require.NoError(t, err)
	readme, err := os.ReadFile(filepath.Join("..", "..", "README.md"))
	require.NoError(t, err)

	for name, re := range map[string]struct {
		text string
		re   *regexp.Regexp
	}{
		"sample":         {string(sample), keyLine},
		"default-config": {defaults, keyLine},
		"README table":   {string(readme), regexp.MustCompile("(?m)^\\| `([A-Za-z0-9]+)` \\|")},
	} {
		var keys []string
		for _, m := range re.re.FindAllStringSubmatch(re.text, -1) {
			if m[1] != configurationKey && !slices.Contains(keys, m[1]) {
				keys = append(keys, m[1])
			}
		}
		slices.Sort(keys)
		assert.Equal(t, configurationKeys(), keys, name)
	}
}
