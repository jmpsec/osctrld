package main

import (
	"log"

	"github.com/urfave/cli/v2"
)

// OsctrldCommands keeps all commands for osctrld
type OsctrldCommands struct {
	Config *JSONConfiguration
}

// CreateCommands to initialize the commands struct
func CreateCommands(config *JSONConfiguration) *OsctrldCommands {
	return &OsctrldCommands{Config: config}
}

func (actions *OsctrldCommands) EnrollNode(c *cli.Context) error {
	log.Printf("Enrolling node")
	return nil
}

func (actions *OsctrldCommands) GetFlags(c *cli.Context) error {
	log.Printf("Getting flags")
	return nil
}

func (actions *OsctrldCommands) RemoveNode(c *cli.Context) error {
	log.Printf("Removing node")
	return nil
}

func (actions *OsctrldCommands) VerifyNode(c *cli.Context) error {
	log.Printf("Verifying node")
	return nil
}
