/*********************************************************************
 * Copyright (c) Intel Corporation 2021
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/
package utils

type ReturnCode int

var ProjectVersion string = "Development Build"

const (
	// ProjectName is the name of the executable
	ProjectName = "rpc"
	// ProjectVersion is the full version of this executable
	ProtocolVersion = "4.0.0"
	// ClientName is the name of the exectable
	ClientName = "RPC"

	// LMSAddress is used for determining what address to connect to LMS on
	LMSAddress = "localhost"
	// LMSPort is used for determining what port to connect to LMS on
	LMSPort    = "16992"
	LMSTLSPort = "16993"

	AMTUserName = "admin"

	// MPSServerMaxLength is the max length of the servername
	MPSServerMaxLength = 256

	HelpHeader = "\nRemote Provisioning Client (RPC) - used for activation, deactivation, maintenance and status of AMT\n\n"

	CommandActivate    = "activate"
	CommandAMTInfo     = "amtinfo"
	CommandDeactivate  = "deactivate"
	CommandMaintenance = "maintenance"
	CommandVersion     = "version"
	CommandConfigure   = "configure"

	SubCommandAddWifiSettings     = "addwifisettings"
	SubCommandWireless            = "wireless"
	SubCommandAddEthernetSettings = "wiredsettings"
	SubCommandWired               = "wired"
	SubCommandEnableWifiPort      = "enablewifiport"
	SubCommandSetMEBx             = "mebx"
	SubCommandConfigureTLS        = "tls"
	SubCommandChangePassword      = "changepassword"
	SubCommandChangeAMTPassword   = "amtpassword"
	SubCommandSyncDeviceInfo      = "syncdeviceinfo"
	SubCommandSyncClock           = "syncclock"
	SubCommandSyncTime            = "synctime"
	SubCommandSyncHostname        = "synchostname"
	SubCommandSyncIP              = "syncip"
	SubCommandSetAMTFeatures      = "amtfeatures"
	SubCommandEnableAMT           = "enableamt"
	SubCommandDisableAMT          = "disableamt"
	SubCommandCIRA                = "cira"

	// Return Codes
	Success ReturnCode = 0
)

// (1-99) General Errors

// (1-19) Basic errors outside of Device Management Toolkit
var (
	IncorrectPermissions  = CustomError{Code: 1, Message: "IncorrectPermissions"}
	HECIDriverNotDetected = CustomError{Code: 2, Message: "HECIDriverNotDetected"}
	AmtNotDetected        = CustomError{Code: 3, Message: "AmtNotDetected"}
	AmtNotReady           = CustomError{Code: 4, Message: "AmtNotReady"}
	HelpRequested         = CustomError{Code: 5, Message: "flag: help requested"}
	GenericFailure        = CustomError{Code: 10, Message: "GenericFailure"}
)

// (20-69) Input errors to RPC
var (
	MissingOrIncorrectURL              = CustomError{Code: 20, Message: "MissingOrIncorrectURL"}
	MissingOrIncorrectProfile          = CustomError{Code: 21, Message: "MissingOrIncorrectProfile"}
	ServerCerificateVerificationFailed = CustomError{Code: 22, Message: "ServerCerificateVerificationFailed"}
	MissingOrIncorrectPassword         = CustomError{Code: 23, Message: "MissingOrIncorrectPassword"}
	MissingDNSSuffix                   = CustomError{Code: 24, Message: "MissingDNSSuffix"}
	MissingHostname                    = CustomError{Code: 25, Message: "MissingHostname"}
	MissingProxyAddressAndPort         = CustomError{Code: 26, Message: "MissingProxyAddressAndPort"}
	MissingOrIncorrectStaticIP         = CustomError{Code: 27, Message: "MissingOrIncorrectStaticIP"}
	IncorrectCommandLineParameters     = CustomError{Code: 28, Message: "IncorrectCommandLineParameters"}
	MissingOrIncorrectNetworkMask      = CustomError{Code: 29, Message: "MissingOrIncorrectNetworkMask"}
	MissingOrIncorrectGateway          = CustomError{Code: 30, Message: "MissingOrIncorrectGateway"}
	MissingOrIncorrectPrimaryDNS       = CustomError{Code: 31, Message: "MissingOrIncorrectPrimaryDNS"}
	MissingOrIncorrectSecondaryDNS     = CustomError{Code: 32, Message: "MissingOrIncorrectSecondaryDNS"}
	InvalidParameterCombination        = CustomError{Code: 33, Message: "InvalidParameterCombination"}
	FailedReadingConfiguration         = CustomError{Code: 34, Message: "FailedReadingConfiguration"}
	MissingOrInvalidConfiguration      = CustomError{Code: 35, Message: "MissingOrInvalidConfiguration"}
	InvalidUserInput                   = CustomError{Code: 36, Message: "InvalidUserInput"}
	InvalidUUID                        = CustomError{Code: 37, Message: "InvalidUUID"}
	PasswordsDoNotMatch                = CustomError{Code: 38, Message: "PasswordsDoNotMatch"}
)

// (70-99) Connection Errors
var (
	RPSAuthenticationFailed         = CustomError{Code: 70, Message: "RPSAuthenticationFailed"}
	AMTConnectionFailed             = CustomError{Code: 71, Message: "AMTConnectionFailed"}
	OSNetworkInterfacesLookupFailed = CustomError{Code: 72, Message: "OSNetworkInterfacesLookupFailed"}
)

// (100-149) Activation, and configuration errors
var (
	AMTAuthenticationFailed           = CustomError{Code: 100, Message: "AMTAuthenticationFailed"}
	WSMANMessageError                 = CustomError{Code: 101, Message: "WSMANMessageError"}
	ActivationFailed                  = CustomError{Code: 102, Message: "ActivationFailed"}
	NetworkConfigurationFailed        = CustomError{Code: 103, Message: "NetworkConfigurationFailed"}
	CIRAConfigurationFailed           = CustomError{Code: 104, Message: "CIRAConfigurationFailed"}
	TLSConfigurationFailed            = CustomError{Code: 105, Message: "TLSConfigurationFailed"}
	WiFiConfigurationFailed           = CustomError{Code: 106, Message: "WiFiConfigurationFailed"}
	AMTFeaturesConfigurationFailed    = CustomError{Code: 107, Message: "AMTFeaturesConfigurationFailed"}
	Ieee8021xConfigurationFailed      = CustomError{Code: 108, Message: "Ieee8021xConfigurationFailed"}
	UnableToDeactivate                = CustomError{Code: 109, Message: "UnableToDeactivate"}
	DeactivationFailed                = CustomError{Code: 110, Message: "DeactivationFailed"}
	UnableToActivate                  = CustomError{Code: 111, Message: "UnableToActivate"}
	WifiConfigurationWithWarnings     = CustomError{Code: 112, Message: "WifiConfigurationWithWarnings"}
	UnmarshalMessageFailed            = CustomError{Code: 113, Message: "UnmarshalMessageFailed"}
	DeleteConfigsFailed               = CustomError{Code: 114, Message: "DeleteConfigsFailed"}
	MissingOrIncorrectWifiProfileName = CustomError{Code: 116, Message: "MissingOrIncorrectWifiProfileName"}
	MissingIeee8021xConfiguration     = CustomError{Code: 117, Message: "MissingIeee8021xConfiguration"}
	SetMEBXPasswordFailed             = CustomError{Code: 118, Message: "SetMEBXPasswordFailed"}
	ChangeAMTPasswordFailed           = CustomError{Code: 119, Message: "ChangeAMTPasswordFailed"}
	UnableToConfigure                 = CustomError{Code: 120, Message: "UnableToConfigure"}
	ActivationFailedDecode64          = CustomError{Code: 121, Message: "ActivationFailed", Details: "failed to decode the certificate from Base64 format"}
	ActivationFailedWrongCertPass     = CustomError{Code: 122, Message: "ActivationFailed", Details: "provisioning cert password incorrect"}
	ActivationFailedInvalidProvCert   = CustomError{Code: 123, Message: "ActivationFailed", Details: "invalid provisioning certificate"}
	ActivationFailedNoCertFound       = CustomError{Code: 124, Message: "ActivationFailed", Details: "no certificates found"}
	ActivationFailedNoPrivKeys        = CustomError{Code: 125, Message: "ActivationFailed", Details: "no private keys found"}
	ActivationFailedNoRootCertFound   = CustomError{Code: 126, Message: "ActivationFailed", Details: "root certificate not found in the pfx"}
	ActivationFailedGetCertHash       = CustomError{Code: 127, Message: "ActivationFailed", Details: "failed to get certificate hashes"}
	ActivationFailedProvCertNoMatch   = CustomError{Code: 128, Message: "ActivationFailed", Details: "the root of the provisioning certificate does not match any of the trusted roots in AMT"}
	ActivationFailedGeneralSettings   = CustomError{Code: 129, Message: "ActivationFailed", Details: "wsman message error, failed to get general settings"}
	ActivationFailedSetupService      = CustomError{Code: 130, Message: "ActivationFailed", Details: "wsman message error, failed to get host based setup service response"}
	ActivationFailedAddCert           = CustomError{Code: 131, Message: "ActivationFailed", Details: "wsman message error, failed to add certificate to AMT"}
	ActivationFailedGenerateNonce     = CustomError{Code: 132, Message: "ActivationFailed", Details: "failed to generate nonce"}
	ActivationFailedSignString        = CustomError{Code: 133, Message: "ActivationFailed", Details: "failed to create signed string"}
	ActivationFailedGetControlMode    = CustomError{Code: 134, Message: "ActivationFailed", Details: "failed to get control mode"}
	ActivationFailedControlMode       = CustomError{Code: 135, Message: "ActivationFailed", Details: "received invalid control mode"}
	DuplicateKey                      = CustomError{Code: 136, Message: "DuplicateKey", Details: "Key pair already exists"}
	WiredConfigurationFailed          = CustomError{Code: 137, Message: "WiredConfigurationFailed"}
	ActivationFailedCertHash          = CustomError{Code: 138, Message: "ActivationFailed", Details: "leaf certificate hash too long"}
	UnsupportedAMTVersion             = CustomError{Code: 138, Message: "UnsupportedAMTVersion"}
	LMSConnectionFailed               = CustomError{Code: 139, Message: "LMSConnectionFailed", Details: "Failed to connect to LMS. Please install LMS for activation."}
)

// (150-199) Maintenance Errors
var (
	SyncClockFailed      = CustomError{Code: 150, Message: "SyncClockFailed"}
	SyncHostnameFailed   = CustomError{Code: 151, Message: "SyncHostnameFailed"}
	SyncIpFailed         = CustomError{Code: 152, Message: "SyncIpFailed"}
	ChangePasswordFailed = CustomError{Code: 153, Message: "ChangePasswordFailed"}
	SyncDeviceInfoFailed = CustomError{Code: 154, Message: "SyncDeviceInfoFailed"}
)

// (200-299) KPMU

// (300-399) Redfish

// (1000 - 3000) Amt PT Status Code Block
var AmtPtStatusCodeBase = CustomError{Code: 1000, Message: "AmtPtStatusCodeBase"}
