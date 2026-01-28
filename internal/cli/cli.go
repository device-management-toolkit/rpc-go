/*********************************************************************
 * Copyright (c) Intel Corporation 2021
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/

package cli

import (
	"strings"

	"github.com/alecthomas/kong"
	kongyaml "github.com/alecthomas/kong-yaml"
	"github.com/device-management-toolkit/rpc-go/v2/internal/commands"
	"github.com/device-management-toolkit/rpc-go/v2/internal/commands/activate"
	"github.com/device-management-toolkit/rpc-go/v2/internal/commands/configure"
	"github.com/device-management-toolkit/rpc-go/v2/internal/commands/diagnostics"
	"github.com/device-management-toolkit/rpc-go/v2/pkg/amt"
	"github.com/device-management-toolkit/rpc-go/v2/pkg/utils"
	log "github.com/sirupsen/logrus"
)

// Global flags that apply to all commands
type Globals struct {
	// Configuration handling

	LogLevel         string `help:"Set log level" default:"info" enum:"trace,debug,info,warn,error,fatal,panic"`
	JsonOutput       bool   `help:"Output in JSON format" name:"json" short:"j"`
	Verbose          bool   `help:"Enable verbose logging" name:"verbose" short:"v"`
	SkipCertCheck    bool   `help:"Skip certificate verification for remote HTTPS/WSS (RPS) connections (insecure)" name:"skip-cert-check" short:"n"`
	SkipAMTCertCheck bool   `help:"Skip certificate verification when connecting to AMT/LMS over TLS (insecure)" name:"skip-amt-cert-check"`
	TenantID         string `help:"Tenant ID for multi-tenant environments for use with RPS" env:"TENANT_ID" name:"tenantid"`
	LMSAddress       string `help:"LMS address to connect to" default:"localhost" name:"lmsaddress"`
	LMSPort          string `help:"LMS port to connect to" default:"16992" name:"lmsport"`
	AMTPassword      string `help:"AMT admin password applied globally to all AMT operations" name:"password" env:"AMT_PASSWORD"`
}

// CLI represents the complete command line interface
type CLI struct {
	Globals
	// Shared server authentication flags for remote flows (optional)
	commands.ServerAuthFlags

	AmtInfo     commands.AmtInfoCmd        `cmd:"" name:"amtinfo" help:"Display information about AMT status and configuration"`
	Version     commands.VersionCmd        `cmd:"version" help:"Display the current version of RPC and the RPC Protocol version"`
	Activate    activate.ActivateCmd       `cmd:"activate" help:"Activate AMT on the local device or via remote server"`
	Deactivate  commands.DeactivateCmd     `cmd:"deactivate" help:"Deactivate AMT on the local device or via remote server"`
	Configure   configure.ConfigureCmd     `cmd:"configure" help:"Configure AMT settings including ethernet, wireless, TLS, and other features"`
	Diagnostics diagnostics.DiagnosticsCmd `cmd:"diagnostics" aliases:"diag" help:"Collect firmware-level diagnostics"`
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

	helpOpts := kong.HelpOptions{Compact: true}

	// Build kong options with YAML configuration resolver (if file exists)
	kongOpts := []kong.Option{
		kong.Name("rpc"),
		kong.Description("Remote Provisioning Client (RPC) - used for activation, deactivation, maintenance and status of AMT"),
		kong.UsageOnError(),
		kong.DefaultEnvars("RPC"),
		kong.ConfigureHelp(helpOpts),
		kong.Configuration(kongyaml.Loader, "config.yaml"),
		kong.BindToProvider(func() amt.Interface { return amtCommand }),
	}

	parser, err := kong.New(&cli, kongOpts...)
	if err != nil {
		return nil, nil, err
	}

	// Slice off program name if present (os.Args style)
	var parseArgs []string
	if len(args) > 1 {
		parseArgs = args[1:]
	} else {
		parseArgs = []string{}
	}

	ctx, perr := parser.Parse(parseArgs)
	if perr == nil {
		return ctx, &cli, nil
	}

	if len(parseArgs) == 0 || strings.Contains(perr.Error(), "unexpected argument") || strings.Contains(perr.Error(), "unknown flag") {
		return nil, nil, perr
	}

	if strings.Contains(perr.Error(), "expected one of") {
		PrintHelp(parser, helpOpts, parseArgs)

		return nil, &cli, nil
	}

	return nil, nil, perr
}

// PrintHelp prints contextual help by appending --help to the args and re-parsing.
// This leverages Kong's built-in help mechanism which handles partial command trees safely.
func PrintHelp(parser *kong.Kong, opts kong.HelpOptions, args []string) error {
	// Append --help to trigger Kong's help output
	helpArgs := append(args, "--help")
	_, _ = parser.Parse(helpArgs)

	return nil
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

	return ExecuteWithAMT(args, amtCommand)
}

// ExecuteWithAMT runs the parsed command with a provided AMT command (useful for testing)
func ExecuteWithAMT(args []string, amtCommand amt.Interface) error {
	// Parse command line with AMT command bound for validation
	kctx, cli, err := Parse(args, amtCommand)
	if err != nil {
		return err
	}

	controlMode, err := amtCommand.GetControlMode()
	if err != nil {
		log.Error(err)

		return utils.AMTConnectionFailed
	}

	// Create shared context
	// Propagate AMT TLS skip preference globally for AMTBaseCmd.AfterApply
	commands.DefaultSkipAMTCertCheck = cli.SkipAMTCertCheck

	appCtx := &commands.Context{
		AMTCommand:       amtCommand,
		ControlMode:      controlMode,
		LogLevel:         cli.LogLevel,
		JsonOutput:       cli.JsonOutput,
		Verbose:          cli.Verbose,
		SkipCertCheck:    cli.SkipCertCheck,
		SkipAMTCertCheck: cli.SkipAMTCertCheck,
		TenantID:         cli.TenantID,
		AMTPassword:      cli.AMTPassword,
		ServerAuthFlags:  cli.ServerAuthFlags,
	}

	// Execute the selected command
	if kctx == nil {
		return nil
	}

	return kctx.Run(appCtx)
}
