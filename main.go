package main

import (
	"log"
	"os"

	"github.com/urfave/cli/v2"
)

const (
	// Application name
	appName string = "osctrld"
	// Application version
	appVersion string = OsctrldVersion
	// Application usage
	appUsage string = "Daemon for osctrl"
	// Application description
	appDescription string = appUsage + ", to manage secret, flags and osquery deployment"
)

const (
	// Default configuration file
	defConfigFile = "osctrld.json"
	// Default secret file
	defSecretFile = "osctrl.secret"
	// Default flag file
	defFlagFile = "osctrl.flags"
	// Default empty value
	defEmptyValye = ""
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
	configFile   string
	secretFile   string
	enrollSecret string
	flagFile     string
	osctrlHost   string
	versionFlag  bool
	insecureFlag bool
)

// Initialization code
func init() {
	// Initialize CLI flags
	flags = []cli.Flag{
		&cli.StringFlag{
			Name:        "configuration",
			Aliases:     []string{"c", "conf", "config"},
			Value:       defConfigFile,
			Usage:       "Configuration file for osctrld to load all necessary values",
			EnvVars:     []string{"OSCTRL_CONFIG"},
			Destination: &configFile,
		},
		&cli.StringFlag{
			Name:        "secret",
			Aliases:     []string{"s"},
			Value:       defEmptyValye,
			Usage:       "Enroll secret to authenticate against osctrl server",
			EnvVars:     []string{"OSCTRL_SECRET"},
			Destination: &enrollSecret,
		},
		&cli.StringFlag{
			Name:        "environment",
			Aliases:     []string{"e", "env"},
			Value:       defEmptyValye,
			Usage:       "Environment in osctrl to enrolled nodes to",
			EnvVars:     []string{"OSCTRL_ENV"},
			Destination: &enrollSecret,
		},
		&cli.StringFlag{
			Name:        "secret-file",
			Aliases:     []string{"S"},
			Value:       defSecretFile,
			Usage:       "Use `FILE` as secret file for osctrl enrolled osquery nodes",
			EnvVars:     []string{"SECRET_FILE"},
			Destination: &secretFile,
		},
		&cli.StringFlag{
			Name:        "flagfile",
			Aliases:     []string{"F"},
			Value:       defFlagFile,
			Usage:       "Use `FILE` as flagfile for osctrl enrolled osquery nodes",
			EnvVars:     []string{"FLAG_FILE"},
			Destination: &flagFile,
		},
		&cli.StringFlag{
			Name:        "osctrl-url",
			Aliases:     []string{"U"},
			Value:       defEmptyValye,
			Usage:       "URL for the osctrl server. https:// is added by default",
			EnvVars:     []string{"OSCTRL_URL"},
			Destination: &osctrlHost,
		},
		&cli.BoolFlag{
			Name:        "insecure",
			Aliases:     []string{"i"},
			Value:       false,
			Usage:       "Force the use of http:// URL for osctrl and ignore warnings",
			EnvVars:     []string{"INSECURE_TLS"},
			Destination: &insecureFlag,
		},
	}
	// Initialize CLI flags commands
	commands = []*cli.Command{}
}

// Function to wrap actions
func cliWrapper(action func(*cli.Context) error) func(*cli.Context) error {
	return func(c *cli.Context) error {
		return action(c)
	}
}

// Action to run when no flags are provided
func cliAction(c *cli.Context) error {
	if c.NumFlags() == 0 {
		if err := cli.ShowAppHelp(c); err != nil {
			log.Fatalf("Error with osctrld help - %s", err)
		}
		return cli.Exit("\nNo flags provided", 2)
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
