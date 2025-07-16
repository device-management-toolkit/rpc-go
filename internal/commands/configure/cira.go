/*********************************************************************
 * Copyright (c) Intel Corporation 2024
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/

package configure

import (
	"errors"
	"fmt"
	"net/url"

	"github.com/device-management-toolkit/go-wsman-messages/v2/pkg/wsman/amt/environmentdetection"
	"github.com/device-management-toolkit/rpc-go/v2/internal/commands"
	"github.com/device-management-toolkit/rpc-go/v2/pkg/utils"
	"github.com/google/uuid"
	log "github.com/sirupsen/logrus"
)

// CIRACmd represents CIRA configuration
type CIRACmd struct {
	ConfigureBaseCmd

	MPSPassword          string   `help:"MPS Password" env:"MPS_PASSWORD" name:"mpspassword"`
	MPSAddress           string   `help:"MPS Address" env:"MPS_ADDRESS" name:"mpsaddress"`
	MPSCert              string   `help:"MPS Root Public Certificate" env:"MPS_CERT" name:"mpscert"`
	EnvironmentDetection []string `help:"Environment Detection (comma separated)" env:"ENVIRONMENT_DETECTION" name:"envdetection"`
}

// BeforeApply validates the CIRA configuration command before execution
func (cmd *CIRACmd) Validate() error {
	// First call the base Validate to handle password validation
	if err := cmd.ConfigureBaseCmd.Validate(); err != nil {
		return err
	}

	// Validate MPS password - prompt if not provided
	if cmd.MPSPassword == "" {
		fmt.Print("MPS Password: ")

		password, err := utils.PR.ReadPassword()
		if err != nil {
			return fmt.Errorf("failed to read MPS password: %w", err)
		}

		cmd.MPSPassword = password
	}

	// Validate MPS address is provided
	if cmd.MPSAddress == "" {
		return fmt.Errorf("MPS address is required for CIRA configuration")
	}

	// Validate MPS address format
	if err := cmd.validateURL(cmd.MPSAddress); err != nil {
		return fmt.Errorf("invalid MPS address format: %w", err)
	}

	// Validate MPS certificate is provided
	if cmd.MPSCert == "" {
		return fmt.Errorf("MPS certificate is required for CIRA configuration")
	}

	// Set default environment detection if not provided
	if len(cmd.EnvironmentDetection) == 0 || cmd.EnvironmentDetection[0] == "" {
		cmd.EnvironmentDetection = []string{uuid.NewString() + ".com"}
		log.Info("Using generated environment detection string: ", cmd.EnvironmentDetection[0])
	}

	return nil
}

// Run executes the CIRA configuration command
func (cmd *CIRACmd) Run(ctx *commands.Context) error {
	log.Info("Configuring CIRA (Cloud-Initiated Remote Access)...")

	// Validate that device is activated before configuring CIRA
	controlMode := cmd.GetControlMode()

	// Device must be activated (not in pre-provisioning state)
	if controlMode == 0 {
		log.Error(ErrDeviceNotActivated)

		return errors.New(ErrDeviceNotActivated)
	}

	// Clear existing CIRA configuration
	err := cmd.clearCIRA()
	if err != nil {
		return fmt.Errorf("failed to clear existing CIRA configuration: %w", err)
	}

	// Add trusted root certificate
	_, err = cmd.WSMan.AddTrustedRootCert(cmd.MPSCert)
	if err != nil {
		if err.Error() == "Root Certificate already exists and must be removed before continuing" {
			log.Warn("Root Certificate already exists. Continuing with the existing certificate.")
		} else {
			return fmt.Errorf("failed to add trusted root certificate: %w", err)
		}
	} else {
		log.Info("successfully added the trusted root certificate")
	}

	// Add MPS server
	_, err = cmd.WSMan.AddMPS(cmd.MPSPassword, cmd.MPSAddress, 4433)
	if err != nil {
		return fmt.Errorf("failed to add MPS server: %w", err)
	}

	log.Info("successfully added the mps server")

	// Get MPS Service Access Points
	results, err := cmd.WSMan.GetMPSSAP()
	if err != nil {
		return fmt.Errorf("failed to get MPS SAP: %w", err)
	}

	if len(results) < 1 {
		return errors.New("no MPS found")
	}

	// Add remote access policy rule for periodic
	_, err = cmd.WSMan.AddRemoteAccessPolicyRule(2, results[0].Name)
	if err != nil {
		return fmt.Errorf("failed to add periodic remote access policy rule: %w", err)
	}

	log.Info("successfully added the remote access policy rule for periodic")

	// Add remote access policy rule for user initiated
	_, err = cmd.WSMan.AddRemoteAccessPolicyRule(0, results[0].Name)
	if err != nil {
		return fmt.Errorf("failed to add user-initiated remote access policy rule: %w", err)
	}

	log.Info("successfully added the remote access policy rule for user initiated")

	// Get remote access policies
	results6, err := cmd.WSMan.GetRemoteAccessPolicies()
	if err != nil {
		return fmt.Errorf("failed to get remote access policies: %w", err)
	}

	// Configure MPS for user initiated policy
	_, err = cmd.WSMan.PutRemoteAccessPolicyAppliesToMPS(results6[1])
	if err != nil {
		return fmt.Errorf("failed to configure MPS for user-initiated policy: %w", err)
	}

	log.Info("successfully configured the configured mps for user initiated policy")

	// Configure MPS for periodic policy
	_, err = cmd.WSMan.PutRemoteAccessPolicyAppliesToMPS(results6[0])
	if err != nil {
		return fmt.Errorf("failed to configure MPS for periodic policy: %w", err)
	}

	log.Info("successfully configured the configured mps for periodic policy")

	// Request state change to enable CIRA
	_, err = cmd.WSMan.RequestStateChangeCIRA()
	if err != nil {
		return fmt.Errorf("failed to enable CIRA: %w", err)
	}

	log.Info("successfully enabled CIRA")

	// Configure environment detection settings
	results9, err := cmd.WSMan.GetEnvironmentDetectionSettings()
	if err != nil {
		return fmt.Errorf("failed to get environment detection settings: %w", err)
	}

	data := environmentdetection.EnvironmentDetectionSettingDataRequest{
		DetectionStrings:           cmd.EnvironmentDetection,
		ElementName:                results9.ElementName,
		InstanceID:                 results9.InstanceID,
		DetectionAlgorithm:         results9.DetectionAlgorithm,
		DetectionIPv6LocalPrefixes: results9.DetectionIPv6LocalPrefixes,
	}

	_, err = cmd.WSMan.PutEnvironmentDetectionSettings(data)
	if err != nil {
		return fmt.Errorf("failed to configure environment detection settings: %w", err)
	}

	log.Info("successfully configured environment detection settings for CIRA")

	log.Info("CIRA configuration completed successfully")

	return nil
}

// Helper methods for CIRA configuration

func (cmd *CIRACmd) validateURL(u string) error {
	parsedURL, err := url.Parse(u)
	if err != nil {
		return err
	}

	if parsedURL.Scheme == "" || parsedURL.Host == "" {
		return errors.New("url is missing scheme or host")
	}

	return nil
}

func (cmd *CIRACmd) clearCIRA() error {
	rapResults, err := cmd.WSMan.GetRemoteAccessPolicies()
	if err != nil {
		return err
	}

	if len(rapResults) > 0 {
		err = cmd.WSMan.RemoveRemoteAccessPolicyRules()
		if err != nil {
			return err
		}
	}

	results, err := cmd.WSMan.GetMPSSAP()
	if err != nil {
		return err
	}

	for _, result := range results {
		err := cmd.WSMan.RemoveMPSSAP(result.Name)
		if err != nil {
			return err
		}
	}

	return nil
}
