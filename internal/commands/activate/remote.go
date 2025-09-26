/*********************************************************************
 * Copyright (c) Intel Corporation 2024
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/

package activate

import (
	"encoding/json"
	"fmt"

	"github.com/device-management-toolkit/rpc-go/v2/internal/commands"
	"github.com/device-management-toolkit/rpc-go/v2/internal/rps"
	"github.com/device-management-toolkit/rpc-go/v2/pkg/utils"
	log "github.com/sirupsen/logrus"
)

// RemoteActivateCmd handles remote AMT activation via RPS
type RemoteActivateCmd struct {
	// Required for remote activation
	URL     string `help:"RPS server URL" required:"" short:"u"`
	Profile string `help:"Profile name to use" env:"PROFILE" required:""`

	// Common flags
	DNS      string `help:"DNS suffix override" env:"DNS_SUFFIX" short:"d"`
	Hostname string `help:"Hostname override" env:"HOSTNAME" short:"h"`

	// Optional remote-specific settings
	UUID         string `help:"UUID override (prevents MPS connection)" name:"uuid"`
	FriendlyName string `help:"Friendly name to associate with this device" name:"name"`
	Proxy        string `help:"Proxy server URL for RPS connection" env:"PROXY" name:"proxy"`

	// Authentication to the remote server (optional for websockets today but reserved for future)
	commands.ServerAuthFlags
}

// RemoteActivationConfig holds the configuration for remote activation
type RemoteActivationConfig struct {
	URL          string
	Profile      string
	DNS          string
	Hostname     string
	UUID         string
	FriendlyName string
	Proxy        string
}

// RemoteActivationService handles the actual remote activation logic
type RemoteActivationService struct {
	config  RemoteActivationConfig
	context *commands.Context
}

// NewRemoteActivationService creates a new remote activation service
func NewRemoteActivationService(config RemoteActivationConfig, ctx *commands.Context) *RemoteActivationService {
	return &RemoteActivationService{
		config:  config,
		context: ctx,
	}
}

// Validate implements Kong's validation interface for remote activation
func (cmd *RemoteActivateCmd) Validate() error {
	// Additional validation for UUID override warning
	if cmd.UUID != "" {
		log.Warn("Overriding UUID prevents device from connecting to MPS")
	}

	return nil
}

// Run executes the remote activation command
func (cmd *RemoteActivateCmd) Run(ctx *commands.Context) error {
	log.Infof("Starting remote AMT activation via RPS server: %s", cmd.URL)

	// Convert Kong CLI flags to activation config
	config := cmd.toActivationConfig()

	// Create and run the activation service
	service := NewRemoteActivationService(config, ctx)

	return service.Activate()
}

// toActivationConfig converts Kong CLI flags to RemoteActivationConfig
func (cmd *RemoteActivateCmd) toActivationConfig() RemoteActivationConfig {
	return RemoteActivationConfig{
		URL:          cmd.URL,
		Profile:      cmd.Profile,
		DNS:          cmd.DNS,
		Hostname:     cmd.Hostname,
		UUID:         cmd.UUID,
		FriendlyName: cmd.FriendlyName,
		Proxy:        cmd.Proxy,
	}
}

// Activate performs the remote AMT activation
func (service *RemoteActivationService) Activate() error {
	log.Infof("Connecting to RPS server: %s", service.config.URL)
	log.Infof("Using profile: %s", service.config.Profile)

	// Step 1: Validate RPS connection
	if err := service.validateRPSConnection(); err != nil {
		return err
	}

	// Step 2: Prepare device information
	deviceInfo := service.prepareDeviceInfo()

	// Step 3: Request activation from RPS
	result, err := service.requestActivation(deviceInfo)
	if err != nil {
		return err
	}

	// Step 4: Output results
	return service.outputResult(result)
}

// validateRPSConnection validates the connection to the RPS server
func (service *RemoteActivationService) validateRPSConnection() error {
	// TODO: Implement RPS connection validation
	log.Debug("Validating RPS connection...")

	// For now, just validate URL format
	if service.config.URL == "" {
		return fmt.Errorf("RPS server URL is required")
	}

	log.Debug("RPS connection validation passed")

	return nil
}

// prepareDeviceInfo prepares device information for RPS
func (service *RemoteActivationService) prepareDeviceInfo() map[string]interface{} {
	log.Debug("Preparing device information...")

	deviceInfo := map[string]interface{}{
		"profile": service.config.Profile,
	}

	// Add optional fields if provided
	if service.config.DNS != "" {
		deviceInfo["dns"] = service.config.DNS
	}

	if service.config.Hostname != "" {
		deviceInfo["hostname"] = service.config.Hostname
	}

	if service.config.UUID != "" {
		deviceInfo["uuid"] = service.config.UUID
	}

	if service.config.FriendlyName != "" {
		deviceInfo["friendly_name"] = service.config.FriendlyName
	}

	return deviceInfo
}

// requestActivation sends activation request to RPS
func (service *RemoteActivationService) requestActivation(deviceInfo map[string]interface{}) (map[string]interface{}, error) {
	log.Info("Sending activation request to RPS...")

	// Build RPS request directly (no internal/flags dependency)
	req := &rps.Request{
		Command:          utils.CommandActivate,
		URL:              service.config.URL,
		Profile:          service.config.Profile,
		DNS:              service.config.DNS,
		Hostname:         service.config.Hostname,
		UUID:             service.config.UUID,
		FriendlyName:     service.config.FriendlyName,
		Proxy:            service.config.Proxy,
		LogLevel:         service.context.LogLevel,
		JsonOutput:       service.context.JsonOutput,
		Verbose:          service.context.Verbose,
		SkipCertCheck:    service.context.SkipCertCheck,
		SkipAmtCertCheck: service.context.SkipAMTCertCheck,
		ControlMode:      service.context.ControlMode,
	}

	// Execute activation via RPS
	err := rps.ExecuteCommand(req)
	if err != nil {
		return nil, fmt.Errorf("RPS activation failed: %w", err)
	}

	// Create success result for our Kong CLI pattern
	result := map[string]interface{}{
		"status":        "success",
		"message":       "Device activated successfully via RPS",
		"rps_server":    service.config.URL,
		"profile":       service.config.Profile,
		"friendly_name": service.config.FriendlyName,
		"device_info":   deviceInfo,
	}

	return result, nil
}

// outputResult outputs the activation result
func (service *RemoteActivationService) outputResult(result map[string]interface{}) error {
	if service.context.JsonOutput {
		jsonBytes, err := json.MarshalIndent(result, "", "  ")
		if err != nil {
			return fmt.Errorf("failed to marshal JSON: %w", err)
		}

		fmt.Println(string(jsonBytes))

		return nil
	}

	// Pretty print for non-JSON output
	log.Info("Status: Device activated successfully via RPS")
	log.Infof("RPS Server: %s\n", service.config.URL)
	log.Infof("Profile: %s\n", service.config.Profile)

	if service.config.FriendlyName != "" {
		log.Infof("Friendly Name: %s\n", service.config.FriendlyName)
	}

	return nil
}
