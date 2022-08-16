package main

import (
	"fmt"
	"log"
	"os"
	"runtime"
	"strings"

	"github.com/urfave/cli/v2"
)

const (
	// Application name
	appName = "osctrld"
	// Application version
	appVersion = OsctrldVersion
	// Application usage
	appUsage = "Daemon for osctrl"
	// Application description
	appDescription = appUsage + ", to manage secret, flags and osquery deployment"
)

const (
	// Default secret file
	defSecretFile = "osquery.secret"
	// Default flag file
	defFlagFile = "osquery.flags"
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
	DarwinOS     = "darwin"
	DarwinFlag   = defDarwinPath + defFlagFile
	DarwinSecret = defDarwinPath + defSecretFile
	// LinuxOS value for GOOS
	LinuxOS     = "linux"
	LinuxFlag   = defLinuxPath + defFlagFile
	LinuxSecret = defLinuxPath + defSecretFile
	// WindowsOS value for GOOS
	WindowsOS     = "windows"
	WindowsFlag   = defWindowsPath + defFlagFile
	WindowsSecret = defWindowsPath + defSecretFile
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
	configFile     string
	jsonConfig     JSONConfiguration
	osctrlCommands *OsctrldCommands
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
			Destination: &jsonConfig.Secret,
		},
		&cli.StringFlag{
			Name:        "environment",
			Aliases:     []string{"e", "env"},
			Value:       defEmptyValue,
			Usage:       "Environment in osctrl to enrolled nodes to",
			EnvVars:     []string{"OSCTRL_ENV"},
			Destination: &jsonConfig.Environment,
		},
		&cli.StringFlag{
			Name:        "secret-file",
			Aliases:     []string{"S"},
			Value:       defEmptyValue,
			Usage:       "Use `FILE` as secret file for osquery. Default depends on OS",
			EnvVars:     []string{"OSQUERY_SECRET"},
			Destination: &jsonConfig.SecretFile,
		},
		&cli.StringFlag{
			Name:        "flagfile",
			Aliases:     []string{"F"},
			Value:       defEmptyValue,
			Usage:       "Use `FILE` as flagfile for osquery. Default depends on OS",
			EnvVars:     []string{"OSQUERY_FLAGFILE"},
			Destination: &jsonConfig.FlagFile,
		},
		&cli.StringFlag{
			Name:        "osctrl-url",
			Aliases:     []string{"U"},
			Value:       defEmptyValue,
			Usage:       "URL for the osctrl server. https:// is added by default",
			EnvVars:     []string{"OSCTRL_URL"},
			Destination: &jsonConfig.URL,
		},
		&cli.BoolFlag{
			Name:        "insecure",
			Aliases:     []string{"i"},
			Value:       false,
			Usage:       "Force the use of http:// URL for osctrl and ignore warnings",
			EnvVars:     []string{"OSCTRL_INSECURE"},
			Destination: &jsonConfig.Insecure,
		},
		&cli.BoolFlag{
			Name:        "verbose",
			Aliases:     []string{"V"},
			Value:       false,
			Usage:       "Enable verbose informational messages",
			EnvVars:     []string{"OSCTRL_VERBOSE"},
			Destination: &jsonConfig.Verbose,
		},
	}
	// Initialize CLI flags commands
	commands = []*cli.Command{
		{
			Name:   "enroll",
			Usage:  "Enroll a new node in osctrl, using new secret and flag files",
			Action: cliWrapper(osctrlCommands.EnrollNode),
		},
		{
			Name:   "remove",
			Usage:  "Remove enrolled node from osctrl, clearing secret and flag files",
			Action: cliWrapper(osctrlCommands.RemoveNode),
		},
		{
			Name:   "verify",
			Usage:  "Verify enrolled node from osctrl",
			Action: cliWrapper(osctrlCommands.VerifyNode),
		},
		{
			Name:   "flags",
			Usage:  "Retrieve flags for osquery from osctrl",
			Action: cliWrapper(osctrlCommands.GetFlags),
		},
	}
}

// Function to wrap actions
func cliWrapper(action func(*cli.Context) error) func(*cli.Context) error {
	return func(c *cli.Context) error {
		if configFile != defEmptyValue {
			jsonConfig, err = loadConfiguration(configFile, c.Bool("verbose"))
			if err != nil {
				exitError := fmt.Sprintf("\n ❌ Error reading configuration file (%s) - %v", configFile, err)
				return cli.Exit(exitError, 2)
			}
		}
		// Based on OS, assign values for flag and secret file, if they have not been assigned already
		switch runtime.GOOS {
		case DarwinOS:
			if jsonConfig.FlagFile == defEmptyValue {
				jsonConfig.FlagFile = DarwinFlag
			}
			if jsonConfig.SecretFile == defEmptyValue {
				jsonConfig.SecretFile = DarwinSecret
			}
		case LinuxOS:
			if jsonConfig.FlagFile == defEmptyValue {
				jsonConfig.FlagFile = LinuxFlag
			}
			if jsonConfig.SecretFile == defEmptyValue {
				jsonConfig.SecretFile = LinuxSecret
			}
		case WindowsOS:
			if jsonConfig.FlagFile == defEmptyValue {
				jsonConfig.FlagFile = WindowsFlag
			}
			if jsonConfig.SecretFile == defEmptyValue {
				jsonConfig.SecretFile = WindowsSecret
			}
		}
		// Check for required parameters
		if jsonConfig.Environment == defEmptyValue {
			exitError := fmt.Sprintf("\n ❌ Environment is required")
			return cli.Exit(exitError, 2)
		}
		if jsonConfig.URL == defEmptyValue {
			exitError := fmt.Sprintf("\n ❌ URL is required")
			return cli.Exit(exitError, 2)
		}
		if jsonConfig.Insecure && strings.HasPrefix(strings.ToLower(jsonConfig.URL), "https://") {
			exitError := fmt.Sprintf("\n ❌ URL can not be HTTPS with Insecure activated")
			return cli.Exit(exitError, 2)
		}
		if jsonConfig.Verbose {
			log.Printf("⏳ Initializing %s...", appName)
			log.Printf("🔎 Flag file: %s", jsonConfig.FlagFile)
			log.Printf("🔑 Secret file: %s", jsonConfig.SecretFile)
			log.Printf("🔗 URL: %s", jsonConfig.URL)
			log.Printf("📍 Environment: %s", jsonConfig.Environment)
			log.Printf("🔓 Insecure: %v", jsonConfig.Insecure)
			log.Printf("📢 Verbose: %v", jsonConfig.Verbose)
			log.Printf("Command %s", c.Command.Name)
		}
		// Initialize actions
		osctrlCommands = CreateCommands(&jsonConfig)
		return action(c)
	}
}

// Action to run when no flags are provided
func cliAction(c *cli.Context) error {
	if c.NumFlags() == 0 {
		if err := cli.ShowAppHelp(c); err != nil {
			log.Fatalf("Error with help - %s", err)
		}
		return cli.Exit(" ❌ No flags provided", 2)
	}
	if c.Command.Name == "" {
		if err := cli.ShowAppHelp(c); err != nil {
			log.Fatalf("Error with help - %s", err)
		}
		return cli.Exit(" ❌ Invalid command", 2)
	}
	return nil
}

// Go go!
func main() {
	// Let's go!
	app = cli.NewApp()
	app.Name = appName
	app.Usage = appUsage
	app.Version = appVersion
	app.Description = appDescription
	app.Flags = flags
	app.Commands = commands
	app.Action = cliAction
	if err := app.Run(os.Args); err != nil {
		log.Fatalf("Failed to execute %v", err)
	}
}
