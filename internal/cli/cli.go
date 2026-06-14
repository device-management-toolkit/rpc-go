/*********************************************************************
 * Copyright (c) Intel Corporation 2021
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/

package cli

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/alecthomas/kong"
	kongyaml "github.com/alecthomas/kong-yaml"
	"github.com/charmbracelet/lipgloss"
	"github.com/device-management-toolkit/rpc-go/v2/internal/commands"
	"github.com/device-management-toolkit/rpc-go/v2/internal/commands/activate"
	"github.com/device-management-toolkit/rpc-go/v2/internal/commands/configure"
	"github.com/device-management-toolkit/rpc-go/v2/internal/commands/diagnostics"
	"github.com/device-management-toolkit/rpc-go/v2/pkg/amt"
	"github.com/device-management-toolkit/rpc-go/v2/pkg/utils"
	"github.com/muesli/termenv"
	log "github.com/sirupsen/logrus"
	"golang.org/x/term"
)

const configFilePath = "config.yaml"

// Global flags that apply to all commands
type Globals struct {
	// Configuration handling

	LogLevel         string `help:"Set log level" default:"info" enum:"trace,debug,info,warn,error,fatal,panic"`
	JsonOutput       bool   `help:"Output in JSON format" name:"json" short:"j"`
	TableOutput      bool   `help:"Output in table format" name:"table" short:"t"`
	NoColor          bool   `help:"Disable colored output" name:"no-color" env:"NO_COLOR"`
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

	// Set color profile explicitly in both branches so behavior is deterministic
	// per invocation (e.g., tests calling Parse multiple times in-process).
	if g.NoColor || !term.IsTerminal(int(os.Stdout.Fd())) {
		g.NoColor = true

		lipgloss.SetColorProfile(termenv.Ascii)
	} else {
		lipgloss.SetColorProfile(termenv.ColorProfile())
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
		kong.Configuration(kongyaml.Loader, configFilePath),
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

	// Log config file presence after parsing (logging is configured by AfterApply at this point)
	if _, statErr := os.Stat(configFilePath); statErr == nil {
		log.Infof("Using configuration file: %s (flag values may originate from this file)", configFilePath)
	}

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

// knownCommands lists the valid top-level command names for hasCommand detection.
var knownCommands = map[string]bool{
	"amtinfo": true, "version": true, "activate": true,
	"deactivate": true, "configure": true, "diagnostics": true, "diag": true,
}

// hasCommand checks if args contain a recognized command name.
func hasCommand(args []string) bool {
	for _, arg := range args[1:] {
		if knownCommands[arg] {
			return true
		}
	}

	return false
}

// hasFlag checks if any of the given flags appear in args.
func hasFlag(args []string, flags ...string) bool {
	for _, arg := range args[1:] {
		for _, flag := range flags {
			if arg == flag {
				return true
			}
		}
	}

	return false
}

// Execute runs the parsed command with proper context.
// HECI initialization is handled by AMTBaseCmd.AfterApply within Kong's
// lifecycle — commands that don't embed AMTBaseCmd (e.g. version) never
// touch HECI, and amtinfo degrades gracefully when HECI is unavailable.
func Execute(args []string) error {
	// Default to amtinfo when no command is specified,
	// but let --help/-h pass through so Kong shows the full command list.
	if !hasCommand(args) && !hasFlag(args, "--help", "-h") {
		newArgs := make([]string, 0, len(args)+1)
		newArgs = append(newArgs, args[0], "amtinfo")
		newArgs = append(newArgs, args[1:]...)
		args = newArgs
	}

	err := ExecuteWithAMT(args, amt.NewAMTCommand())

	// If a command failed due to insufficient privileges, offer auto-elevation.
	// Use errors.As to unwrap any Kong error wrapping.
	var customErr utils.CustomError
	if errors.As(err, &customErr) && customErr.Code == utils.IncorrectPermissions.Code &&
		!utils.IsElevated() && term.IsTerminal(int(os.Stdin.Fd())) {
		fmt.Print("\nThis command requires administrator privileges. Re-run as administrator? [y/N]: ")

		var response string

		fmt.Scanln(&response)

		if strings.EqualFold(strings.TrimSpace(response), "y") {
			if elevErr := utils.SelfElevate(); elevErr != nil {
				return fmt.Errorf("failed to elevate: %w", elevErr)
			}

			return nil
		}
	}

	return err
}

// ExecuteWithAMT runs the parsed command with a provided AMT command.
// Used by the C library entry point (lib.go) which manages its own
// pre-initialization before calling this function.
func ExecuteWithAMT(args []string, amtCommand amt.Interface) error {
	kctx, cli, err := Parse(args, amtCommand)
	if err != nil {
		return err
	}

	if kctx == nil {
		return nil
	}

	commands.DefaultSkipAMTCertCheck = cli.SkipAMTCertCheck

	appCtx := &commands.Context{
		AMTCommand:       amtCommand,
		LocalTLSEnforced: false,
		LogLevel:         cli.LogLevel,
		JsonOutput:       cli.JsonOutput,
		TableOutput:      cli.TableOutput,
		NoColor:          cli.NoColor,
		Verbose:          cli.Verbose,
		SkipCertCheck:    cli.SkipCertCheck,
		SkipAMTCertCheck: cli.SkipAMTCertCheck,
		TenantID:         cli.TenantID,
		AMTPassword:      cli.AMTPassword,
		ServerAuthFlags:  cli.ServerAuthFlags,
	}

	return kctx.Run(appCtx)
}
