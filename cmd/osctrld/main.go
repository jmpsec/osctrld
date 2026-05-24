package main

import (
	"os"
	"runtime"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/urfave/cli/v2"
)

const (
	// Application name
	appName = "osctrld"
	// Application version
	appVersion = OsctrldVersion
	// Application usage
	appUsage = "Daemon for osctrl, the fast and efficient osquery management"
	// Application description
	appDescription = appUsage + ", to manage secret, flags and osquery deployment"
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
)

const (
	// DarwinOS value for GOOS
	DarwinOS = "darwin"
	// LinuxOS value for GOOS
	LinuxOS = "linux"
	// WindowsOS value for GOOS
	WindowsOS = "windows"
)

// Global variables
var (
	err      error
	app      *cli.App
	flags    []cli.Flag
	commands []*cli.Command
)

// Variables for flags
var (
	configFile string
	appConfig Configuration
	osctrlURLs OsctrlURLs
)

// Initialization code
func init() {
	// Initialize CLI flags
	flags = []cli.Flag{
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
			Usage:       "Enroll secret to authenticate against osctrl server",
			EnvVars:     []string{"OSCTRL_SECRET"},
			Destination: &appConfig.Secret,
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
			Usage:       "Use `FILE` as secret file for osquery. Default depends on OS",
			EnvVars:     []string{"OSQUERY_SECRET"},
			Destination: &appConfig.SecretFile,
		},
		&cli.StringFlag{
			Name:        "flagfile",
			Aliases:     []string{"F"},
			Value:       defEmptyValue,
			Usage:       "Use `FILE` as flagfile for osquery. Default depends on OS",
			EnvVars:     []string{"OSQUERY_FLAGFILE"},
			Destination: &appConfig.FlagFile,
		},
		&cli.StringFlag{
			Name:        "certificate",
			Aliases:     []string{"C"},
			Value:       defEmptyValue,
			Usage:       "Use `FILE` as certificate for osquery, if needed. Default depends on OS",
			EnvVars:     []string{"OSQUERY_CERTIFICATE"},
			Destination: &appConfig.CertFile,
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
			Value:       "text",
			Usage:       "Log output format: text or json",
			EnvVars:     []string{"OSCTRL_LOG_FORMAT"},
			Destination: &appConfig.LogFormat,
		},
		&cli.IntFlag{
			Name:        "interval",
			Aliases:     []string{"I"},
			Value:       60,
			Usage:       "Sync interval in minutes for service mode",
			EnvVars:     []string{"OSCTRL_INTERVAL"},
			Destination: &appConfig.Interval,
		},
	}
	// Initialize CLI flags commands
	commands = []*cli.Command{
		{
			Name:   "enroll",
			Usage:  "Enroll a new node in osctrl, using new secret and flag files",
			Action: cliWrapper(enrollNode),
		},
		{
			Name:   "remove",
			Usage:  "Remove enrolled node from osctrl, clearing secret and flag files",
			Action: cliWrapper(removeNode),
		},
		{
			Name:   "verify",
			Usage:  "Verify flags, cert and secret for an enrolled node in osctrl",
			Action: cliWrapper(verifyNode),
		},
		{
			Name:  "flags",
			Usage: "Retrieve flags for osquery from osctrl and write them locally",
			Action: cliWrapper(func(c *cli.Context) error {
				_, err := getFlags(c)
				return err
			}),
		},
		{
			Name:  "cert",
			Usage: "Retrieve server certificate for osquery from osctrl and write it locally",
			Action: cliWrapper(func(c *cli.Context) error {
				_, err := getCert(c)
				return err
			}),
		},
		{
			Name:   "service",
			Usage:  "Run as a daemon, periodically syncing flags and certificate",
			Action: cliWrapper(serviceNode),
		},
	}
}

// Function to wrap actions
func cliWrapper(action func(*cli.Context) error) func(*cli.Context) error {
	return func(c *cli.Context) error {
		if configFile != defEmptyValue {
			appConfig, err = loadConfiguration(configFile, c.Bool("verbose"))
			if err != nil {
				log.Error().Str("path", configFile).Err(err).Msg("error reading configuration file")
				return cli.Exit("", 2)
			}
		}
		zerolog.SetGlobalLevel(zerolog.InfoLevel)
		if appConfig.Verbose {
			zerolog.SetGlobalLevel(zerolog.DebugLevel)
		}
		if appConfig.LogFormat == "json" {
			log.Logger = zerolog.New(os.Stderr).With().Timestamp().Logger()
		} else {
			log.Logger = zerolog.New(zerolog.ConsoleWriter{Out: os.Stderr}).With().Timestamp().Logger()
		}
		log.Debug().Str("app", appName).Msg("initializing")
		// Based on OS, assign values for flag and secret file, if they have not been assigned already
		switch runtime.GOOS {
		case DarwinOS:
			if appConfig.OsqueryPath == defEmptyValue {
				appConfig.OsqueryPath = defDarwinPath
			}
			if appConfig.FlagFile == defEmptyValue {
				appConfig.FlagFile = genFullPath(appConfig.OsqueryPath, defFlagFile)
			}
			if appConfig.SecretFile == defEmptyValue {
				appConfig.SecretFile = genFullPath(appConfig.OsqueryPath, defSecretFile)
			}
			if appConfig.CertFile == defEmptyValue {
				appConfig.CertFile = genFullPath(appConfig.OsqueryPath, defCertificate)
			}
			if appConfig.EnrollScript == "" {
				appConfig.EnrollScript = genFullPath(appConfig.OsqueryPath, defEnrollScript+shExtension)
			}
			if appConfig.RemoveScript == "" {
				appConfig.RemoveScript = genFullPath(appConfig.OsqueryPath, defRemoveScript+shExtension)
			}
			if appConfig.ExtensionsDir == "" {
				appConfig.ExtensionsDir = genFullPath(appConfig.OsqueryPath, "extensions/")
			}
		case LinuxOS:
			if appConfig.OsqueryPath == defEmptyValue {
				appConfig.OsqueryPath = defLinuxPath
			}
			if appConfig.FlagFile == defEmptyValue {
				appConfig.FlagFile = genFullPath(appConfig.OsqueryPath, defFlagFile)
			}
			if appConfig.SecretFile == defEmptyValue {
				appConfig.SecretFile = genFullPath(appConfig.OsqueryPath, defSecretFile)
			}
			if appConfig.CertFile == defEmptyValue {
				appConfig.CertFile = genFullPath(appConfig.OsqueryPath, defCertificate)
			}
			if appConfig.EnrollScript == "" {
				appConfig.EnrollScript = genFullPath(appConfig.OsqueryPath, defEnrollScript+shExtension)
			}
			if appConfig.RemoveScript == "" {
				appConfig.RemoveScript = genFullPath(appConfig.OsqueryPath, defRemoveScript+shExtension)
			}
			if appConfig.ExtensionsDir == "" {
				appConfig.ExtensionsDir = genFullPath(appConfig.OsqueryPath, "extensions/")
			}
		case WindowsOS:
			if appConfig.OsqueryPath == defEmptyValue {
				appConfig.OsqueryPath = defWindowsPath
			}
			if appConfig.FlagFile == defEmptyValue {
				appConfig.FlagFile = genFullPath(appConfig.OsqueryPath, defFlagFile)
			}
			if appConfig.SecretFile == defEmptyValue {
				appConfig.SecretFile = genFullPath(appConfig.OsqueryPath, defSecretFile)
			}
			if appConfig.CertFile == defEmptyValue {
				appConfig.CertFile = genFullPath(appConfig.OsqueryPath, defCertificate)
			}
			if appConfig.EnrollScript == "" {
				appConfig.EnrollScript = genFullPath(appConfig.OsqueryPath, defEnrollScript+ps1Extension)
			}
			if appConfig.RemoveScript == "" {
				appConfig.RemoveScript = genFullPath(appConfig.OsqueryPath, defRemoveScript+ps1Extension)
			}
			if appConfig.ExtensionsDir == "" {
				appConfig.ExtensionsDir = genFullPath(appConfig.OsqueryPath, "extensions/")
			}
		}
		// Check for required parameters
		if appConfig.Environment == defEmptyValue {
			log.Error().Msg("environment for osctrl is required")
			return cli.Exit("", 2)
		}
		if appConfig.BaseURL == defEmptyValue {
			log.Error().Msg("base URL for osctrl is required")
			return cli.Exit("", 2)
		}
		// Initialize URLs
		osctrlURLs = genURLs(appConfig.BaseURL, appConfig.Environment, appConfig.Insecure)
		log.Debug().
			Str("osquery_path", appConfig.OsqueryPath).
			Str("flag_file", appConfig.FlagFile).
			Str("secret_file", appConfig.SecretFile).
			Str("cert_file", appConfig.CertFile).
			Str("enroll_script", appConfig.EnrollScript).
			Str("remove_script", appConfig.RemoveScript).
			Str("base_url", appConfig.BaseURL).
			Str("environment", appConfig.Environment).
			Bool("insecure", appConfig.Insecure).
			Bool("verbose", appConfig.Verbose).
			Bool("force", appConfig.Force).
			Str("command", c.Command.Name).
			Msg("configuration loaded")
		return action(c)
	}
}

// Action to run when no flags are provided
func cliAction(c *cli.Context) error {
	if c.NumFlags() == 0 {
		if err := cli.ShowAppHelp(c); err != nil {
			log.Fatal().Err(err).Msg("error showing help")
		}
		log.Error().Msg("no command provided")
		return cli.Exit("", 2)
	}
	if c.Command.Name == "" {
		if err := cli.ShowAppHelp(c); err != nil {
			log.Fatal().Err(err).Msg("error showing help")
		}
		log.Error().Msg("invalid command")
		return cli.Exit("", 2)
	}
	return nil
}

// buildApp creates and configures the CLI application
func buildApp() *cli.App {
	a := cli.NewApp()
	a.Name = appName
	a.Usage = appUsage
	a.Version = appVersion
	a.Description = appDescription
	a.Flags = flags
	a.Commands = commands
	a.Action = cliAction
	return a
}

// Go go!
func main() {
	// Let's go!
	app = buildApp()
	if err := app.Run(os.Args); err != nil {
		log.Fatal().Err(err).Msg("failed to execute")
	}
}
