/*********************************************************************
 * Copyright (c) Intel Corporation 2021
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/

package cli

import (
	"strings"

	"github.com/alecthomas/kong"
	"github.com/device-management-toolkit/rpc-go/v2/internal/amt"
	"github.com/device-management-toolkit/rpc-go/v2/internal/commands"
	"github.com/device-management-toolkit/rpc-go/v2/internal/commands/activate"
	"github.com/device-management-toolkit/rpc-go/v2/internal/config"
	log "github.com/sirupsen/logrus"
)

// Global flags that apply to all commands
type Globals struct {
	Config           string `help:"Path to configuration file" name:"config" type:"path" default:"config.yaml"`
	LogLevel         string `help:"Set log level" name:"log-level" default:"info" enum:"trace,debug,info,warn,error,fatal,panic"`
	JsonOutput       bool   `help:"Output in JSON format" name:"json" short:"j"`
	Verbose          bool   `help:"Enable verbose logging" name:"verbose" short:"v"`
	LocalTLSEnforced bool   `help:"Enforce local TLS for connections" name:"local-tls"`
	SkipCertCheck    bool   `help:"Skip certificate verification (insecure)" name:"skip-cert-check" short:"n"`
}

// CLI represents the complete command line interface
type CLI struct {
	Globals

	AmtInfo    commands.AmtInfoCmd    `cmd:"" name:"amtinfo" help:"Display information about AMT status and configuration"`
	Version    commands.VersionCmd    `cmd:"version" help:"Display the current version of RPC and the RPC Protocol version"`
	Activate   activate.ActivateCmd   `cmd:"activate" help:"Activate AMT on the local device or via remote server"`
	Deactivate commands.DeactivateCmd `cmd:"deactivate" help:"Deactivate AMT on the local device or via remote server"`

	// Configuration loaded from YAML file (not directly accessible via CLI)
	Config config.Config `kong:"-"`
}

// AfterApply sets up the context and applies global settings after flags are parsed
func (g *Globals) AfterApply(ctx *kong.Context) error {
	// Configure logging based on flags
	if g.Verbose {
		log.SetLevel(log.TraceLevel)
	} else {
		lvl, err := log.ParseLevel(g.LogLevel)
		if err != nil {
			log.Warn(err)
			log.SetLevel(log.InfoLevel)
		} else {
			log.SetLevel(lvl)
		}
	}

	// Configure log format
	if g.JsonOutput {
		log.SetFormatter(&log.JSONFormatter{
			DisableHTMLEscape: true,
		})
	} else {
		log.SetFormatter(&log.TextFormatter{
			DisableColors: true,
			FullTimestamp: true,
		})
	}

	return nil
}

// Parse creates a new Kong parser and parses the command line
func Parse(args []string, amtCommand amt.Interface) (*kong.Context, *CLI, error) {
	var cli CLI

	// First, do a preliminary parse to get the config file path
	var configFile = "config.yaml" // default

	// Check if --config is specified in args
	for i, arg := range args {
		if arg == "--config" && i+1 < len(args) {
			configFile = args[i+1]

			break
		} else if strings.HasPrefix(arg, "--config=") {
			configFile = strings.TrimPrefix(arg, "--config=")

			break
		}
	}

	log.Debugf("Using configuration file: %s", configFile)

	// Create legacy resolver for backwards compatibility with existing config.yaml
	legacyResolver, err := ConfigResolver(configFile)
	if err != nil {
		return nil, nil, err
	}

	parser, err := kong.New(&cli,
		kong.Name("rpc"),
		kong.Description("Remote Provisioning Client (RPC) - used for activation, deactivation, maintenance and status of AMT"),
		kong.UsageOnError(),
		kong.Resolvers(legacyResolver), // Add legacy resolver for backwards compatibility
		kong.DefaultEnvars("RPC"),
		kong.ConfigureHelp(kong.HelpOptions{
			Compact: true,
		}),
		kong.BindToProvider(func() amt.Interface { return amtCommand }), // Bind AMTCommand using provider
	)
	if err != nil {
		return nil, nil, err
	}

	// Handle empty args case
	var parseArgs []string
	if len(args) > 1 {
		parseArgs = args[1:] // Skip program name
	} else {
		parseArgs = []string{} // Empty slice for empty input
	}

	ctx, err := parser.Parse(parseArgs)
	if err != nil {
		return nil, nil, err
	}

	return ctx, &cli, nil
}

// Execute runs the parsed command with proper context
func Execute(args []string) error {
	// Check AMT access first
	amtCommand := amt.NewAMTCommand()
	if err := amtCommand.Initialize(); err != nil {
		log.Error("Failed to execute due to access issues. " +
			"Please ensure that Intel ME is present, " +
			"the MEI driver is installed, " +
			"and the runtime has administrator or root privileges.")

		return err
	}

	// Parse command line with AMT command bound for validation
	kctx, cli, err := Parse(args, amtCommand)
	if err != nil {
		return err
	}

	// Create shared context
	appCtx := &commands.Context{
		AMTCommand:       amtCommand,
		LogLevel:         cli.LogLevel,
		JsonOutput:       cli.JsonOutput,
		Verbose:          cli.Verbose,
		LocalTLSEnforced: cli.LocalTLSEnforced,
		SkipCertCheck:    cli.SkipCertCheck,
	}

	// Execute the selected command
	return kctx.Run(appCtx)
}
