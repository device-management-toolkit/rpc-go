/*********************************************************************
 * Copyright (c) Intel Corporation 2024
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/
package local

import (
	"strings"

	"github.com/open-amt-cloud-toolkit/go-wsman-messages/v2/pkg/wsman/amt/redirection"
	"github.com/open-amt-cloud-toolkit/go-wsman-messages/v2/pkg/wsman/cim/kvm"
	"github.com/open-amt-cloud-toolkit/go-wsman-messages/v2/pkg/wsman/ips/optin"
	"github.com/open-amt-cloud-toolkit/rpc-go/v2/pkg/utils"
	log "github.com/sirupsen/logrus"
)

func (service *ProvisioningService) SetAMTFeatures() error {
	log.Info("configuring AMT Features")

	// Determine the redirection state
	isRedirectionChanged := service.flags.KVM || service.flags.SOL || service.flags.IDER

	// Get the current redirection state
	getResponse, err := service.interfacedWsmanMessage.GetRedirectionService()
	if err != nil {
		log.Error("Error while getting the redirection state: ", err)
		return utils.AMTFeaturesConfigurationFailed
	}
	// Set the AMT Redirection service if true
	if err := service.setAMTRedirectionService(); err != nil {
		log.Error("Error while setting the redirection state: ", err)
		return utils.AMTFeaturesConfigurationFailed
	}

	// Set the KVM State
	isISMSystem, err := service.isISMSystem()
	if err != nil {
		log.Error("Error while getting the System type: ", err)
		return utils.AMTFeaturesConfigurationFailed
	}
	if !isISMSystem {
		var kvmStateEnabled kvm.KVMRedirectionSAPRequestStateChangeInput
		kvmStateEnabled = 3 // 3 (Disabled) - to disable the network interface of the feature
		if service.flags.KVM {
			kvmStateEnabled = 2 // 2 (Enabled) - to enable the network interface of the feature
		}
		if _, err := service.interfacedWsmanMessage.RequestKVMStateChange(kvmStateEnabled); err != nil {
			log.Error("Error while setting the KVM state: ", err)
			return utils.AMTFeaturesConfigurationFailed
		}
	}

	if isISMSystem && service.flags.KVM {
		log.Warn("KVM is not supported on ISM systems")
	}

	// Put the redirection service
	if err := service.putRedirectionService(getResponse.Body.GetAndPutResponse, isRedirectionChanged); err != nil {
		log.Error("Error while putting the redirection service: ", err)
		return utils.AMTFeaturesConfigurationFailed
	}

	//Get OptInService
	getOptInServiceResponse, err := service.interfacedWsmanMessage.GetIpsOptInService()
	if err != nil {
		log.Error("Error while getting the OptIn Service: ", err)
		return utils.AMTFeaturesConfigurationFailed
	}
	var optInRequired uint32
	optInRequired = uint32(getOptInServiceResponse.Body.GetAndPutResponse.OptInRequired)
	switch service.flags.UserConsent {
	case "none":
		optInRequired = uint32(optin.OptInRequiredNone)
	case "kvm":
		optInRequired = uint32(optin.OptInRequiredKVM)
	case "all":
		optInRequired = uint32(optin.OptInRequiredAll)
	}
	if uint32(getOptInServiceResponse.Body.GetAndPutResponse.OptInRequired) != optInRequired {
		//Put OptInService
		request := optin.OptInServiceRequest{
			CanModifyOptInPolicy:    int(getOptInServiceResponse.Body.GetAndPutResponse.CanModifyOptInPolicy),
			CreationClassName:       getOptInServiceResponse.Body.GetAndPutResponse.CreationClassName,
			ElementName:             getOptInServiceResponse.Body.GetAndPutResponse.ElementName,
			Name:                    getOptInServiceResponse.Body.GetAndPutResponse.Name,
			OptInCodeTimeout:        getOptInServiceResponse.Body.GetAndPutResponse.OptInCodeTimeout,
			OptInDisplayTimeout:     getOptInServiceResponse.Body.GetAndPutResponse.OptInDisplayTimeout,
			OptInRequired:           int(optInRequired),
			OptInState:              int(getOptInServiceResponse.Body.GetAndPutResponse.OptInState),
			SystemCreationClassName: getOptInServiceResponse.Body.GetAndPutResponse.SystemCreationClassName,
			SystemName:              getOptInServiceResponse.Body.GetAndPutResponse.SystemName,
		}
		_, err := service.interfacedWsmanMessage.PutIpsOptInService(request)
		if err != nil {
			log.Error("Error while putting the OptIn Service: ", err)
			return utils.AMTFeaturesConfigurationFailed
		}
	}

	// Get the AMT Features
	println("AMT Features configured successfully")
	if !isISMSystem {
		println("KVM Enabled		:", service.flags.KVM)
	}
	println("SOL Enabled		:", service.flags.SOL)
	println("IDER Enabled		:", service.flags.IDER)
	println("User Consent		:", service.flags.UserConsent)

	return nil
}

func (service *ProvisioningService) setAMTRedirectionService() error {
	var requestedState redirection.RequestedState
	requestedState = 32768 //supported values in RequestedState are 32768-32771
	if service.flags.IDER {
		requestedState += 1
	}
	if service.flags.SOL {
		requestedState += 2
	}
	//32771 - enable IDER and SOL
	_, err := service.interfacedWsmanMessage.RequestRedirectionStateChange(requestedState)
	if err != nil {
		return err
	}
	return nil
}

func (service *ProvisioningService) putRedirectionService(getResponse redirection.RedirectionResponse, isRedirectionChanged bool) error {
	// Construct put redirection Request from get redirection response
	redirRequest := redirection.RedirectionRequest{
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
	_, err := service.interfacedWsmanMessage.PutRedirectionState(redirRequest)
	if err != nil {
		return err
	}
	return nil
}
func (service *ProvisioningService) isISMSystem() (bool, error) {
	dataStruct := make(map[string]interface{})
	result, err := service.amtCommand.GetVersionDataFromME("AMT", service.flags.AMTTimeoutDuration)
	if err != nil {
		log.Error(err)
		return false, err
	}
	dataStruct["amt"] = result
	result, err = service.amtCommand.GetVersionDataFromME("Sku", service.flags.AMTTimeoutDuration)
	if err != nil {
		log.Error(err)
		return false, err
	}
	dataStruct["sku"] = result
	result = DecodeAMT(dataStruct["amt"].(string), dataStruct["sku"].(string))
	dataStruct["features"] = strings.TrimSpace(result)
	if strings.Contains(dataStruct["features"].(string), "Intel Standard Manageability") {
		return true, nil
	}
	return false, nil
}
