/*********************************************************************
 * Copyright (c) Intel Corporation 2024
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/

package configure

import (
	"fmt"
	"strings"

	"github.com/device-management-toolkit/go-wsman-messages/v2/pkg/wsman/amt/redirection"
	"github.com/device-management-toolkit/go-wsman-messages/v2/pkg/wsman/cim/kvm"
	"github.com/device-management-toolkit/go-wsman-messages/v2/pkg/wsman/ips/optin"
	"github.com/device-management-toolkit/rpc-go/v2/internal/commands"
	"github.com/device-management-toolkit/rpc-go/v2/pkg/utils"
	log "github.com/sirupsen/logrus"
)

// AMTFeaturesCmd represents AMT features configuration
type AMTFeaturesCmd struct {
	ConfigureBaseCmd

	UserConsent string `help:"Sets user consent (ACM only)" enum:"kvm,all,none" name:"userConsent" default:"all"`
	KVM         bool   `help:"Enable KVM (Keyboard, Video, Mouse). If omitted, KVM will be disabled when other flags are also omitted." name:"kvm"`
	SOL         bool   `help:"Enable SOL (Serial Over LAN). If omitted, SOL will be disabled when other flags are also omitted." name:"sol"`
	IDER        bool   `help:"Enable IDER (IDE Redirection). If omitted, IDER will be disabled when other flags are also omitted." name:"ider"`
	// DisableAll is an internal flag used by the profile orchestrator to explicitly
	// disable all features when the profile sets them to false. Hidden from help.
	DisableAll bool `name:"disableAll" hidden:""`

	// Provisioning certificate (for mutual TLS after ACM activation)
	ProvisioningCertFlag    string `help:"Provisioning certificate (base64 encoded)" env:"PROVISIONING_CERT" name:"provisioningCert"`
	ProvisioningCertPwdFlag string `help:"Provisioning certificate password" env:"PROVISIONING_CERT_PASSWORD" name:"provisioningCertPwd"`
}

// Validate implements Kong's Validate interface for AMT features validation
func (cmd *AMTFeaturesCmd) Validate() error {
	// First call the base Validate to handle password validation
	if err := cmd.ConfigureBaseCmd.Validate(); err != nil {
		return err
	}

	// Backward compatibility: by default, require at least one feature or user consent.
	// Allow an internal override when DisableAll is explicitly set (used by orchestrator).
	featuresSpecified := cmd.KVM || cmd.SOL || cmd.IDER || cmd.UserConsent != ""
	if !featuresSpecified && !cmd.DisableAll {
		return fmt.Errorf("no AMT features specified for configuration. Use --kvm, --sol, --ider flags or --userConsent to configure features")
	}

	return nil
}

// Run executes the AMT features configuration command
func (cmd *AMTFeaturesCmd) Run(ctx *commands.Context) error {
	// Copy provisioning certificate from flags to base command for mutual TLS
	if cmd.ProvisioningCertFlag != "" {
		cmd.ProvisioningCert = cmd.ProvisioningCertFlag
		cmd.ProvisioningCertPwd = cmd.ProvisioningCertPwdFlag
	}

	// Ensure runtime initialization (password + WSMAN client)
	if err := cmd.EnsureRuntime(ctx); err != nil {
		return err
	}

	log.Info("configuring AMT Features")

	// Device must be activated (not in pre-provisioning state)
	if cmd.GetControlMode() == 0 {
		log.Error(ErrDeviceNotActivated)

		return ErrDeviceNotActivated
	}

	// Determine the redirection state
	isRedirectionChanged := cmd.KVM || cmd.SOL || cmd.IDER

	// Get the current redirection state
	getResponse, err := cmd.WSMan.GetRedirectionService()
	if err != nil {
		log.Error("Error while getting the redirection state: ", err)

		return utils.AMTFeaturesConfigurationFailed
	}

	// Set the AMT Redirection service if true
	if err := cmd.setAMTRedirectionService(); err != nil {
		log.Error("Error while setting the redirection state: ", err)

		return utils.AMTFeaturesConfigurationFailed
	}

	// Set the KVM State
	isISMSystem, err := cmd.isISMSystem(ctx)
	if err != nil {
		log.Error("Error while getting the System type: ", err)

		return utils.AMTFeaturesConfigurationFailed
	}

	if !isISMSystem {
		var kvmStateEnabled kvm.KVMRedirectionSAPRequestStateChangeInput

		kvmStateEnabled = 3 // 3 (Disabled) - to disable the network interface of the feature
		if cmd.KVM {
			kvmStateEnabled = 2 // 2 (Enabled) - to enable the network interface of the feature
		}

		if _, err := cmd.WSMan.RequestKVMStateChange(kvmStateEnabled); err != nil {
			log.Error("Error while setting the KVM state: ", err)

			return utils.AMTFeaturesConfigurationFailed
		}
	}

	if isISMSystem && cmd.KVM {
		log.Warn("KVM is not supported on ISM systems")
	}

	// Put the redirection service
	if err := cmd.putRedirectionService(getResponse.Body.GetAndPutResponse, isRedirectionChanged); err != nil {
		log.Error("Error while putting the redirection service: ", err)

		return utils.AMTFeaturesConfigurationFailed
	}

	if cmd.GetControlMode() == 2 {
		// Get OptInService
		getOptInServiceResponse, err := cmd.WSMan.GetIpsOptInService()
		if err != nil {
			log.Error("Error while getting the OptIn Service: ", err)

			return utils.AMTFeaturesConfigurationFailed
		}

		optInRequired := getOptInServiceResponse.Body.GetAndPutResponse.OptInRequired

		switch cmd.UserConsent {
		case "none":
			optInRequired = uint32(optin.OptInRequiredNone)
		case "kvm":
			optInRequired = uint32(optin.OptInRequiredKVM)
		case "all":
			optInRequired = uint32(optin.OptInRequiredAll)
		}

		if getOptInServiceResponse.Body.GetAndPutResponse.OptInRequired != optInRequired {
			// Put OptInService
			request := optin.OptInServiceRequest{
				CanModifyOptInPolicy:    getOptInServiceResponse.Body.GetAndPutResponse.CanModifyOptInPolicy,
				CreationClassName:       getOptInServiceResponse.Body.GetAndPutResponse.CreationClassName,
				ElementName:             getOptInServiceResponse.Body.GetAndPutResponse.ElementName,
				Name:                    getOptInServiceResponse.Body.GetAndPutResponse.Name,
				OptInCodeTimeout:        getOptInServiceResponse.Body.GetAndPutResponse.OptInCodeTimeout,
				OptInDisplayTimeout:     getOptInServiceResponse.Body.GetAndPutResponse.OptInDisplayTimeout,
				OptInRequired:           int(optInRequired),
				OptInState:              getOptInServiceResponse.Body.GetAndPutResponse.OptInState,
				SystemCreationClassName: getOptInServiceResponse.Body.GetAndPutResponse.SystemCreationClassName,
				SystemName:              getOptInServiceResponse.Body.GetAndPutResponse.SystemName,
			}

			_, err := cmd.WSMan.PutIpsOptInService(request)
			if err != nil {
				log.Error("Error while putting the OptIn Service: ", err)

				return utils.AMTFeaturesConfigurationFailed
			}
		}
	}

	// Log the AMT Features
	if isISMSystem {
		log.Warn("KVM feature is not supported on ISM systems.")
	} else {
		log.Info("KVM: ", cmd.KVM)
	}

	log.Info("SOL: ", cmd.SOL)
	log.Info("IDER: ", cmd.IDER)

	if cmd.GetControlMode() != 2 && cmd.UserConsent != "all" {
		log.Warn("User consent is read-only and set to ALL by default in CCM.")
	} else {
		log.Info("User Consent: ", cmd.UserConsent)
	}

	log.Info("AMT Features configured successfully")

	return nil
}

// Helper methods for AMT Features configuration

func (cmd *AMTFeaturesCmd) setAMTRedirectionService() error {
	var requestedState redirection.RequestedState

	requestedState = 32768 // supported values in RequestedState are 32768-32771
	if cmd.IDER {
		requestedState += 1
	}

	if cmd.SOL {
		requestedState += 2
	}
	// 32771 - enable IDER and SOL
	_, err := cmd.WSMan.RequestRedirectionStateChange(requestedState)
	if err != nil {
		return err
	}

	return nil
}

func (cmd *AMTFeaturesCmd) putRedirectionService(getResponse redirection.RedirectionResponse, isRedirectionChanged bool) error {
	// Construct put redirection Request from get redirection response
	redirRequest := &redirection.RedirectionRequest{
		Name:                    getResponse.Name,
		CreationClassName:       getResponse.CreationClassName,
		SystemCreationClassName: getResponse.SystemCreationClassName,
		SystemName:              getResponse.SystemName,
		ElementName:             getResponse.ElementName,
		ListenerEnabled:         isRedirectionChanged,
		EnabledState:            redirection.EnabledState(3),
	}
	if isRedirectionChanged {
		redirRequest.EnabledState = redirection.EnabledState(2)
	}

	_, err := cmd.WSMan.PutRedirectionState(redirRequest)
	if err != nil {
		return err
	}

	return nil
}

func (cmd *AMTFeaturesCmd) isISMSystem(ctx *commands.Context) (bool, error) {
	dataStruct := make(map[string]interface{})

	result, err := ctx.AMTCommand.GetVersionDataFromME("AMT", 5) // Using default timeout
	if err != nil {
		log.Error(err)

		return false, err
	}

	dataStruct["amt"] = result

	result, err = ctx.AMTCommand.GetVersionDataFromME("Sku", 5) // Using default timeout
	if err != nil {
		log.Error(err)

		return false, err
	}

	dataStruct["sku"] = result
	result = utils.DecodeAMTFeatures(dataStruct["amt"].(string), dataStruct["sku"].(string))

	dataStruct["features"] = strings.TrimSpace(result)
	if strings.Contains(dataStruct["features"].(string), "Intel Standard Manageability") {
		return true, nil
	}

	return false, nil
}
