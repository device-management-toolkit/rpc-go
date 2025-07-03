/*********************************************************************
 * Copyright (c) Intel Corporation 2021
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/

package cli

import (
	"github.com/alecthomas/kong"
	"github.com/device-management-toolkit/rpc-go/v2/internal/amt"
	"github.com/device-management-toolkit/rpc-go/v2/internal/commands"
	log "github.com/sirupsen/logrus"
)

// Global flags that apply to all commands
type Globals struct {
	LogLevel         string `help:"Set log level" default:"info" enum:"trace,debug,info,warn,error,fatal,panic"`
	JsonOutput       bool   `help:"Output in JSON format" name:"json" short:"j"`
	Verbose          bool   `help:"Enable verbose logging" short:"v"`
	LocalTLSEnforced bool   `help:"Enforce local TLS for connections" name:"local-tls"`
	SkipCertCheck    bool   `help:"Skip certificate verification (insecure)" name:"skip-cert-check" short:"n"`
}

// CLI represents the complete command line interface
type CLI struct {
	Globals

	AmtInfo    commands.AmtInfoCmd    `cmd:"" name:"amtinfo" help:"Display information about AMT status and configuration"`
	Version    commands.VersionCmd    `cmd:"version" help:"Display the current version of RPC and the RPC Protocol version"`
	Deactivate commands.DeactivateCmd `cmd:"deactivate" help:"Deactivate AMT on the local device or via remote server"`
}

// BeforeApply sets up the context and applies global settings
func (g *Globals) BeforeApply(ctx *kong.Context) error {
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

	parser, err := kong.New(&cli,
		kong.Name("rpc"),
		kong.Description("Remote Provisioning Client (RPC) - used for activation, deactivation, maintenance and status of AMT"),
		kong.UsageOnError(),
		kong.DefaultEnvars(""),
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
