package main

import (
	"context"
	"fmt"
	"os"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/urfave/cli/v3"
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
	app      *cli.Command
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
			Action: cliWrapper(func(ctx context.Context, cmd *cli.Command) error {
				_, err := getFlags(ctx, cmd)
				return err
			}),
		},
		{
			Name:  "cert",
			Usage: "Retrieve server certificate for osquery from osctrl and write it locally",
			Action: cliWrapper(func(ctx context.Context, cmd *cli.Command) error {
				_, err := getCert(ctx, cmd)
				return err
			}),
		},
		{
			Name:   "service",
			Usage:  "Run as a daemon, periodically syncing flags and certificate",
			Action: cliWrapper(serviceNode),
		},
		{
			Name:   "install",
			Usage:  "Enroll this node natively: install osquery if needed, write secret, flags and certificate, and start the service",
			Action: cliWrapper(installNode),
		},
		{
			Name:   "uninstall",
			Usage:  "Remove this node from osctrl natively: stop the service and delete secret, flags and certificate. osquery itself is left installed",
			Action: cliWrapper(uninstallNode),
		},
		{
			Name:    "check-config",
			Aliases: []string{"config-check", "verify-config"},
			Usage:   "Validate configuration and exit",
			Action: cliWrapper(func(ctx context.Context, cmd *cli.Command) error {
				_, err := fmt.Fprintln(cmd.Root().Writer, "configuration is valid")
				return err
			}),
		},
		{
			Name:  "default-config",
			Usage: "Print a default YAML configuration",
			Action: func(ctx context.Context, cmd *cli.Command) error {
				configYAML, err := defaultConfigurationYAML()
				if err != nil {
					return err
				}
				_, err = fmt.Fprint(cmd.Root().Writer, configYAML)
				return err
			},
		},
	}
}

// Function to wrap actions
func cliWrapper(action func(context.Context, *cli.Command) error) func(context.Context, *cli.Command) error {
	return func(ctx context.Context, cmd *cli.Command) error {
		var unknownKeys []string
		if configFile != defEmptyValue {
			appConfig, unknownKeys, err = loadConfiguration(configFile, cmd.Bool("verbose"))
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
		warnUnsafeConfigFile(configFile)
		if configFile != defEmptyValue {
			if ignored := ignoredByConfigFile(); len(ignored) > 0 {
				log.Warn().Str("path", configFile).Strs("ignored", ignored).Msg("the configuration file takes precedence over all flags and environment variables, these are ignored")
			}
		}
		if len(unknownKeys) > 0 {
			// Names only: a misspelled key may still hold a secret
			log.Warn().Str("path", configFile).Strs("keys", unknownKeys).Msg("ignoring unknown configuration keys, check them for typos")
		}
		warnCleartextURLs(appConfig)
		warnRelativePaths(appConfig)
		warnUnusualValues(appConfig)
		// Spinners only make sense for interactive one-shot commands
		initSpinner(appConfig, cmd.Name)
		log.Debug().Str("app", appName).Msg("initializing")
		// Initialize URLs
		osctrlURLs = genURLs(appConfig.BaseURL, appConfig.Environment, appConfig.Insecure)
		logLoadedConfiguration(appConfig, cmd.Name)
		return action(ctx, cmd)
	}
}

// logLoadedConfiguration logs the effective configuration at debug level,
// never the secret, and URLs without userinfo, query or fragment
func logLoadedConfiguration(cfg Configuration, command string) {
	log.Debug().
		Str("osquery_path", cfg.OsqueryPath).
		Str("flag_file", cfg.OsqueryFlagFile).
		Str("secret_file", cfg.OsquerySecretFile).
		Str("cert_file", cfg.OsqueryCertFile).
		Str("enroll_script", cfg.EnrollScript).
		Str("remove_script", cfg.RemoveScript).
		Str("base_url", redactURL(cfg.BaseURL)).
		Str("osquery_package", redactURL(cfg.OsqueryPackage)).
		Str("environment", cfg.Environment).
		Bool("insecure", cfg.Insecure).
		Bool("verbose", cfg.Verbose).
		Bool("force", cfg.Force).
		Str("command", command).
		Msg("configuration loaded")
}

// Action to run when no flags are provided
func cliAction(ctx context.Context, cmd *cli.Command) error {
	if cmd.NumFlags() == 0 {
		if err := cli.ShowRootCommandHelp(cmd); err != nil {
			log.Fatal().Err(err).Msg("error showing help")
		}
		log.Error().Msg("no command provided")
		return cli.Exit("", 2)
	}
	if cmd.Name == "" {
		if err := cli.ShowRootCommandHelp(cmd); err != nil {
			log.Fatal().Err(err).Msg("error showing help")
		}
		log.Error().Msg("invalid command")
		return cli.Exit("", 2)
	}
	return nil
}

// buildApp creates and configures the CLI application
func buildApp() *cli.Command {
	return &cli.Command{
		Name:        appName,
		Usage:       appUsage,
		Version:     buildVersion,
		Description: appDescription,
		Flags: append(flags, &cli.BoolFlag{
			Name:    "version",
			Aliases: []string{"v"},
			Usage:   "Print version information",
			Action: func(ctx context.Context, cmd *cli.Command, b bool) error {
				if b {
					fmt.Fprintln(cmd.Root().Writer, versionString())
					os.Exit(0)
				}
				return nil
			},
		}),
		HideVersion: true,
		Commands:    commands,
		Action:      cliAction,
	}
}

// Go go!
func main() {
	// Let's go!
	app = buildApp()
	if err := app.Run(context.Background(), os.Args); err != nil {
		log.Fatal().Err(err).Msg("failed to execute")
	}
}
