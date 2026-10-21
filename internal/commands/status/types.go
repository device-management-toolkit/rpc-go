/*********************************************************************
 * Copyright (c) Intel Corporation 2026
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/

package status

import "github.com/device-management-toolkit/rpc-go/v2/pkg/amt"

type checkState string

const (
	resultUnknown                 = "unknown"
	resultReady                   = "ready"
	resultConditional             = "conditional"
	resultNotReady                = "not_ready"
	resultNotAMT                  = "not_amt"
	checkPass          checkState = "pass"
	checkWarn          checkState = "warn"
	checkFail          checkState = "fail"
	checkUnavailable   checkState = "unavailable"
	checkNotEvaluated  checkState = "not_evaluated"
	checkAlreadyActive checkState = "already_activated"
)

const (
	checkIDAdmin               = "running_as_admin_root"
	checkIDMEI                 = "mei_driver"
	checkIDActivation          = "amt_activated_state"
	checkIDProvisioningState   = "amt_provisioning_state"
	checkIDRequestedMode       = "requested_control_mode"
	checkIDPostHealth          = "post_activation_health"
	checkIDPlatform            = "platform_type"
	checkIDOperationalState    = "amt_operational_state"
	checkIDVersion             = "amt_version"
	checkIDDNS                 = "dns_suffix"
	checkIDNetwork             = "amt_network_link"
	checkIDLMS                 = "lms"
	checkIDWSMAN               = "wsman_session"
	checkIDConnectionMode      = "amt_connection_mode"
	checkIDRedirection         = "redirection_service"
	checkIDSOL                 = "sol_redirection"
	checkIDUserConsent         = "kvm_user_consent"
	checkIDCIRA                = "cira_configuration"
	checkIDCIRAState           = "cira_connection"
	checkIDTLS                 = "tls_mode"
	checkIDTrustedRoots        = "tls_trusted_roots"
	checkIDKVM                 = "kvm_redirection"
	checkIDMonitor             = "monitor_connected"
	checkIDDirectHost          = "direct_host_reachability"
	checkNameAdmin             = "Running as admin/root"
	checkNameMEI               = "MEI driver"
	checkNameActivation        = "AMT activated state"
	checkNameProvisioningState = "AMT provisioning state"
	checkNameRequestedMode     = "Requested control mode"
	checkNamePostHealth        = "Post-activation health"
	checkNamePlatform          = "Platform type"
	checkNameOperationalState  = "AMT operational state"
	checkNameVersion           = "AMT version"
	checkNameDNS               = "DNS suffix"
	checkNameNetwork           = "AMT network link"
	checkNameLMS               = "LMS"
	checkNameWSMAN             = "Local WSMAN session"
	checkNameConnectionMode    = "AMT connection mode"
	checkNameRedirection       = "Redirection service"
	checkNameSOL               = "SOL redirection"
	checkNameUserConsent       = "KVM user consent"
	checkNameCIRA              = "CIRA configuration"
	checkNameCIRAState         = "CIRA connection"
	checkNameTLS               = "TLS mode"
	checkNameTrustedRoots      = "Trusted root certificates"
	checkNameKVM               = "KVM redirection"
	checkNameMonitor           = "Monitor"
	checkNameDirectHost        = "Direct host reachability"
	checkNameAMTInfo           = "AMT information"
	checkSetPre                = "pre_activation"
	checkSetPreACM             = "pre_activation_acm"
	checkSetPreCCM             = "pre_activation_ccm"
	checkSetPost               = "post_activation"
	deviceTypeISM              = "Intel Standard Manageability"
	statusLinkUp               = "up"
	minSupportedAMTMajor       = 11
	maxSupportedAMTMajor       = 21
)

// Check is one machine-readable readiness observation.
type Check struct {
	ID      string     `json:"id"`
	Name    string     `json:"name"`
	Status  checkState `json:"status"`
	Message string     `json:"message"`
}

// Verdict is the only computed summary consumed by text and JSON output.
type Verdict struct {
	Result             string
	Status             string
	ReadyToProvision   bool
	ReadyForManagement bool
}

type activationProfileReadiness struct {
	Profile          string `json:"profile"`
	Result           string `json:"result"`
	Status           string `json:"status"`
	ReadyToProvision bool   `json:"readyToProvision"`
}

type report struct {
	DetectedState         string
	SelectedCheckSet      string
	DeviceType            string
	AMTVersion            string
	AMTDNSSuffix          string
	OSDNSSuffix           string
	AMTOperationalState   string
	RemoteAccess          *amt.RemoteAccessStatus
	TLSMode               string
	Host                  string
	ProcessorModel        string
	OSDescription         string
	WiredAdapterName      string
	WirelessAdapterName   string
	WiredAdapterStatus    string
	WirelessAdapterStatus string
	Checks                []Check
	Verdict               Verdict
	ActivationProfiles    []activationProfileReadiness
}

type evaluation struct {
	DetectedState         string                       `json:"detectedState"`
	SelectedCheckSet      string                       `json:"selectedCheckSet"`
	DeviceType            string                       `json:"deviceType,omitempty"`
	AMTVersion            string                       `json:"amtVersion,omitempty"`
	AMTDNSSuffix          string                       `json:"amtDnsSuffix,omitempty"`
	OSDNSSuffix           string                       `json:"osDnsSuffix,omitempty"`
	AMTOperationalState   string                       `json:"amtOperationalState,omitempty"`
	RemoteAccess          *amt.RemoteAccessStatus      `json:"remoteAccess,omitempty"`
	TLSMode               string                       `json:"tlsMode,omitempty"`
	Host                  string                       `json:"host,omitempty"`
	ProcessorModel        string                       `json:"processor,omitempty"`
	OSDescription         string                       `json:"os,omitempty"`
	WiredAdapterName      string                       `json:"wiredAdapterName,omitempty"`
	WirelessAdapterName   string                       `json:"wirelessAdapterName,omitempty"`
	WiredAdapterStatus    string                       `json:"wiredAdapterStatus,omitempty"`
	WirelessAdapterStatus string                       `json:"wirelessAdapterStatus,omitempty"`
	ActivationProfiles    []activationProfileReadiness `json:"activationProfiles,omitempty"`
	OverallResult         string                       `json:"overallResult"`
	OverallStatus         string                       `json:"overallStatus"`
	TotalChecks           int                          `json:"totalChecks"`
	Passed                int                          `json:"passed"`
	Warned                int                          `json:"warned"`
	Failed                int                          `json:"failed"`
	NotVerified           int                          `json:"notVerified"`
	ReadyToProvision      bool                         `json:"readyToProvision"`
	ReadyForManagement    bool                         `json:"readyForManagement,omitempty"`
}

type jsonMetadata struct {
	Command          string `json:"command"`
	Timestamp        string `json:"timestamp"`
	RPCVersion       string `json:"rpcVersion"`
	Elevated         bool   `json:"elevated"`
	PasswordProvided bool   `json:"passwordProvided"`
}

type jsonOutput struct {
	Metadata   jsonMetadata `json:"metadata"`
	Evaluation evaluation   `json:"evaluation"`
	Checks     []Check      `json:"checks"`
}
