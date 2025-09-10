/*********************************************************************
 * Copyright (c) Intel Corporation 2025
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/

package profile

import (
	"encoding/json"
	"fmt"

	"github.com/device-management-toolkit/go-wsman-messages/v2/pkg/config"
	"github.com/device-management-toolkit/rpc-go/v2/internal/commands"
	internalconfig "github.com/device-management-toolkit/rpc-go/v2/internal/config"
	"github.com/device-management-toolkit/rpc-go/v2/internal/orchestrator"
	log "github.com/sirupsen/logrus"
)

// ProfileCmd represents the profile command for orchestrating AMT configuration
type ProfileCmd struct {
	// Profile source - mutually exclusive options
	File string `help:"Path to local profile YAML file" short:"f" xor:"source"`
	URL  string `help:"HTTP/S endpoint URL to fetch profile from (supports encrypted responses)" short:"u" xor:"source"`

	// Authentication options for HTTP/S endpoint
	Token    string `help:"JWT token for authentication (for URL source)" env:"PROFILE_TOKEN"`
	Username string `help:"Username for authentication (for URL source)" env:"PROFILE_USERNAME"`
	Password string `help:"Password for authentication (for URL source)" env:"PROFILE_PASSWORD"`

	// Optional overrides
	SkipActivation bool `help:"Skip activation step if device is already activated" default:"false"`
	DryRun         bool `help:"Show what would be executed without making changes" default:"false"`
}

// ProfileResult represents the result of profile execution
type ProfileResult struct {
	Status  string                 `json:"status"`
	Message string                 `json:"message"`
	Profile config.Configuration   `json:"profile,omitempty"`
	Steps   []StepResult          `json:"steps,omitempty"`
	Errors  []string              `json:"errors,omitempty"`
}

// StepResult represents the result of a single orchestration step
type StepResult struct {
	Step    string `json:"step"`
	Status  string `json:"status"`
	Message string `json:"message,omitempty"`
}

// Run executes the profile command
func (cmd *ProfileCmd) Run(ctx *commands.Context) error {
	log.Info("Starting profile orchestration...")

	// Step 1: Load or fetch the profile
	profileConfig, err := cmd.loadProfile(ctx)
	if err != nil {
		return cmd.outputError(ctx, fmt.Errorf("failed to load profile: %w", err))
	}

	// Step 2: Validate the profile
	if err := cmd.validateProfile(profileConfig); err != nil {
		return cmd.outputError(ctx, fmt.Errorf("invalid profile: %w", err))
	}

	// Step 3: Execute the profile orchestration
	result, err := cmd.executeProfile(profileConfig)
	if err != nil {
		return cmd.outputError(ctx, err)
	}

	// Step 4: Output the result
	return cmd.outputResult(ctx, result)
}

// loadProfile loads the profile from file or HTTP/S endpoint
func (cmd *ProfileCmd) loadProfile(ctx *commands.Context) (config.Configuration, error) {
	var cfg config.Configuration

	// Load from file
	if cmd.File != "" {
		log.Infof("Loading profile from file: %s", cmd.File)
		return internalconfig.LoadConfig(cmd.File)
	}

	// Load from HTTP/S endpoint
	if cmd.URL != "" {
		log.Infof("Fetching profile from URL: %s", cmd.URL)
		
		fetcher := &ProfileFetcher{
			URL:           cmd.URL,
			Token:         cmd.Token,
			Username:      cmd.Username,
			Password:      cmd.Password,
			SkipCertCheck: ctx.SkipCertCheck,
		}
		
		return fetcher.FetchProfile()
	}

	return cfg, fmt.Errorf("no profile source specified (use --file or --url)")
}

// validateProfile validates the profile configuration
func (cmd *ProfileCmd) validateProfile(cfg config.Configuration) error {
	// Basic validation - can be extended
	if cfg.Configuration.AMTSpecific.AdminPassword == "" {
		log.Warn("No AMT admin password specified in profile")
	}

	return nil
}

// executeProfile executes the profile orchestration
func (cmd *ProfileCmd) executeProfile(cfg config.Configuration) (*ProfileResult, error) {
	result := &ProfileResult{
		Profile: cfg,
		Steps:   []StepResult{},
	}

	if cmd.DryRun {
		log.Info("DRY RUN MODE - No changes will be made")
		result.Status = "dry_run"
		result.Message = "Profile validation successful (dry run)"
		
		// Add steps that would be executed
		result.Steps = cmd.getDryRunSteps(cfg)
		return result, nil
	}

	// Create and run the orchestrator
	orch := orchestrator.NewProfileOrchestrator(cfg)
	
	// Execute the profile
	err := orch.ExecuteProfile()
	if err != nil {
		result.Status = "failed"
		result.Message = fmt.Sprintf("Profile orchestration failed: %v", err)
		result.Errors = []string{err.Error()}
		return result, err
	}

	result.Status = "success"
	result.Message = "Profile orchestration completed successfully"
	
	return result, nil
}

// getDryRunSteps returns the steps that would be executed in a dry run
func (cmd *ProfileCmd) getDryRunSteps(cfg config.Configuration) []StepResult {
	steps := []StepResult{}

	// Check what steps would be executed
	if cfg.Configuration.AMTSpecific.ControlMode != "" && !cmd.SkipActivation {
		steps = append(steps, StepResult{
			Step:    "activation",
			Status:  "pending",
			Message: fmt.Sprintf("Would activate with control mode: %s", cfg.Configuration.AMTSpecific.ControlMode),
		})
	}

	if cfg.Configuration.AMTSpecific.MEBXPassword != "" && cfg.Configuration.AMTSpecific.ControlMode == "acmactivate" {
		steps = append(steps, StepResult{
			Step:    "mebx_configuration",
			Status:  "pending",
			Message: "Would configure MEBx password",
		})
	}

	redirection := cfg.Configuration.Redirection
	if redirection.Services.KVM || redirection.Services.SOL || redirection.Services.IDER {
		steps = append(steps, StepResult{
			Step:    "amt_features",
			Status:  "pending",
			Message: "Would configure AMT redirection features",
		})
	}

	wired := cfg.Configuration.Network.Wired
	if wired.IPAddress != "" || wired.DHCPEnabled || wired.PrimaryDNS != "" || wired.SecondaryDNS != "" {
		steps = append(steps, StepResult{
			Step:    "wired_network",
			Status:  "pending",
			Message: "Would configure wired network settings",
		})
	}

	if cfg.Configuration.Network.Wireless.WiFiSyncEnabled {
		steps = append(steps, StepResult{
			Step:    "wifi_enable",
			Status:  "pending",
			Message: "Would enable WiFi port",
		})
	}

	if len(cfg.Configuration.Network.Wireless.Profiles) > 0 {
		steps = append(steps, StepResult{
			Step:    "wireless_profiles",
			Status:  "pending",
			Message: fmt.Sprintf("Would configure %d wireless profile(s)", len(cfg.Configuration.Network.Wireless.Profiles)),
		})
	}

	if cfg.Configuration.TLS.Enabled {
		steps = append(steps, StepResult{
			Step:    "tls_configuration",
			Status:  "pending",
			Message: "Would configure TLS settings",
		})
	}

	return steps
}

// outputResult outputs the result in the appropriate format
func (cmd *ProfileCmd) outputResult(ctx *commands.Context, result *ProfileResult) error {
	if ctx.JsonOutput {
		jsonBytes, err := json.MarshalIndent(result, "", "  ")
		if err != nil {
			return fmt.Errorf("failed to marshal JSON: %w", err)
		}
		fmt.Println(string(jsonBytes))
		return nil
	}

	// Text output
	if result.Status == "success" {
		log.Info("✓ Profile orchestration completed successfully")
	} else if result.Status == "dry_run" {
		log.Info("✓ Profile validation successful (dry run mode)")
		if len(result.Steps) > 0 {
			log.Info("Steps that would be executed:")
			for _, step := range result.Steps {
				log.Infof("  - %s: %s", step.Step, step.Message)
			}
		}
	} else {
		log.Error("✗ Profile orchestration failed")
		if len(result.Errors) > 0 {
			for _, err := range result.Errors {
				log.Errorf("  Error: %s", err)
			}
		}
	}

	return nil
}

// outputError outputs an error in the appropriate format
func (cmd *ProfileCmd) outputError(ctx *commands.Context, err error) error {
	if ctx.JsonOutput {
		result := ProfileResult{
			Status:  "error",
			Message: err.Error(),
			Errors:  []string{err.Error()},
		}
		jsonBytes, _ := json.MarshalIndent(result, "", "  ")
		fmt.Println(string(jsonBytes))
	}
	return err
}

// Validate implements Kong's validation interface
func (cmd *ProfileCmd) Validate() error {
	// Ensure at least one source is specified
	if cmd.File == "" && cmd.URL == "" {
		return fmt.Errorf("profile source required: specify either --file or --url")
	}

	// Validate authentication options for URL source
	if cmd.URL != "" {
		if cmd.Token == "" && (cmd.Username == "" || cmd.Password == "") {
			log.Warn("No authentication provided for URL source. Profile endpoint may require authentication.")
		}
	}

	// Warn if authentication options provided for file source
	if cmd.File != "" && (cmd.Token != "" || cmd.Username != "" || cmd.Password != "") {
		log.Warn("Authentication options are ignored when using file source")
	}

	return nil
}