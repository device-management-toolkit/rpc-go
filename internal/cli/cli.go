/*********************************************************************
 * Copyright (c) Intel Corporation 2021
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/

package cli

import (
	"strings"

	"github.com/alecthomas/kong"
	"github.com/device-management-toolkit/go-wsman-messages/v2/pkg/config"
	"github.com/device-management-toolkit/rpc-go/v2/internal/commands"
	"github.com/device-management-toolkit/rpc-go/v2/internal/commands/activate"
	"github.com/device-management-toolkit/rpc-go/v2/internal/commands/configure"
	"github.com/device-management-toolkit/rpc-go/v2/pkg/amt"
	"github.com/device-management-toolkit/rpc-go/v2/pkg/utils"
	log "github.com/sirupsen/logrus"
)

// Global flags that apply to all commands
type Globals struct {
	// Configuration handling
	Config    string `help:"Path to configuration file or SMB share URL. (previously --configv2)" name:"config" type:"path" default:"config.yaml"`
	ConfigKey string `help:"32 byte key to decrypt config file" env:"CONFIG_ENCRYPTION_KEY" name:"configencryptionkey"`

	LogLevel      string `help:"Set log level" default:"info" enum:"trace,debug,info,warn,error,fatal,panic"`
	JsonOutput    bool   `help:"Output in JSON format" name:"json" short:"j"`
	Verbose       bool   `help:"Enable verbose logging" name:"verbose" short:"v"`
	SkipCertCheck bool   `help:"Skip certificate verification (insecure)" name:"skip-cert-check" short:"n"`
	LMSAddress    string `help:"LMS address to connect to" default:"localhost" name:"lmsaddress"`
	LMSPort       string `help:"LMS port to connect to" default:"16992" name:"lmsport"`
}

// CLI represents the complete command line interface
type CLI struct {
	Globals

	AmtInfo    commands.AmtInfoCmd    `cmd:"" name:"amtinfo" help:"Display information about AMT status and configuration"`
	Version    commands.VersionCmd    `cmd:"version" help:"Display the current version of RPC and the RPC Protocol version"`
	Activate   activate.ActivateCmd   `cmd:"activate" help:"Activate AMT on the local device or via remote server"`
	Deactivate commands.DeactivateCmd `cmd:"deactivate" help:"Deactivate AMT on the local device or via remote server"`
	Configure  configure.ConfigureCmd `cmd:"configure" help:"Configure AMT settings including ethernet, wireless, TLS, and other features"`

	// Configuration loaded from YAML file (not directly accessible via CLI)
	YamlConfig config.Configuration `kong:"-"`
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

	// Preliminary scan for --config
	configFile := "config.yaml"

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

	helpOpts := kong.HelpOptions{Compact: true}

	parser, err := kong.New(&cli,
		kong.Name("rpc"),
		kong.Description("Remote Provisioning Client (RPC) - used for activation, deactivation, maintenance and status of AMT"),
		kong.UsageOnError(),
		kong.DefaultEnvars("RPC"),
		kong.ConfigureHelp(helpOpts),
		kong.BindToProvider(func() amt.Interface { return amtCommand }),
	)
	if err != nil {
		return nil, nil, err
	}

	// Slice off program name if present
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

	// Root invocation (no args) or errors unrelated to missing subcommand -> return error unchanged
	if len(parseArgs) == 0 || strings.Contains(perr.Error(), "unexpected argument") || strings.Contains(perr.Error(), "unknown flag") {
		return nil, nil, perr
	}

	// Only intercept classic missing subcommand scenario
	if strings.Contains(perr.Error(), "expected one of") {
		PrintHelp(parser, helpOpts, parseArgs)

		return nil, &cli, nil
	}

	return nil, nil, perr
}

// PrintHelp prints contextual help without invoking the help flag exit path.
func PrintHelp(parser *kong.Kong, opts kong.HelpOptions, args []string) error {
	ctx, err := kong.Trace(parser, args)
	if err != nil {
		return err
	}

	return kong.DefaultHelpPrinter(opts, ctx)
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
	appCtx := &commands.Context{
		AMTCommand:    amtCommand,
		ControlMode:   controlMode,
		LogLevel:      cli.LogLevel,
		JsonOutput:    cli.JsonOutput,
		Verbose:       cli.Verbose,
		SkipCertCheck: cli.SkipCertCheck,
	}

	// Execute the selected command
	if kctx == nil {
		return nil
	}

	return kctx.Run(appCtx)
}
