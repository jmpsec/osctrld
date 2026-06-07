package main

import (
	"fmt"
	"os"

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
	commands []*cli.Command
)

// Initialization code
func init() {
	// Initialize CLI flags
	flags = buildConfigFlags()
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
		{
			Name:    "check-config",
			Aliases: []string{"config-check", "verify-config"},
			Usage:   "Validate configuration and exit",
			Action: cliWrapper(func(c *cli.Context) error {
				_, err := fmt.Fprintln(c.App.Writer, "configuration is valid")
				return err
			}),
		},
		{
			Name:  "default-config",
			Usage: "Print a default YAML configuration",
			Action: func(c *cli.Context) error {
				configYAML, err := defaultConfigurationYAML()
				if err != nil {
					return err
				}
				_, err = fmt.Fprint(c.App.Writer, configYAML)
				return err
			},
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
		applyConfigurationDefaults(&appConfig)
		if err := validateConfiguration(appConfig); err != nil {
			log.Error().Err(err).Msg("invalid configuration")
			return cli.Exit("", 2)
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
		// Initialize URLs
		osctrlURLs = genURLs(appConfig.BaseURL, appConfig.Environment, appConfig.Insecure)
		log.Debug().
			Str("osquery_path", appConfig.OsqueryPath).
			Str("flag_file", appConfig.OsqueryFlagFile).
			Str("secret_file", appConfig.OsquerySecretFile).
			Str("cert_file", appConfig.OsqueryCertFile).
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
