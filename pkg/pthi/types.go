/*********************************************************************
 * Copyright (c) Intel Corporation 2021
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/
package pthi

const (
	GET_REQUEST_SIZE                       uint32 = 12
	MAX_SUFFIX_LENGTH                             = 64
	MAX_DNS_SUFFIXES                              = 5
	CERT_HASH_MAX_LENGTH                          = 64
	CERT_HASH_MAX_NUMBER                          = 33
	NET_TLS_CERT_PKI_MAX_SERIAL_NUMS              = 3
	NET_TLS_CERT_PKI_MAX_SERIAL_NUM_LENGTH        = 16
	MPS_HOSTNAME_LENGTH                           = 256
	IDER_LOG_ENTRIES                              = 6
	MAJOR_VERSION                                 = 1
	MINOR_VERSION                                 = 1
	AMT_MAJOR_VERSION                             = 1
	AMT_MINOR_VERSION                             = 1
	BIOS_VERSION_LEN                              = 65
	VERSIONS_NUMBER                               = 50
	UNICODE_STRING_LEN                            = 20
)

const (
	CFG_MAX_ACL_USER_LENGTH = 33
	CFG_MAX_ACL_PWD_LENGTH  = 33
)

const (
	PROVISIONING_MODE_REQUEST  = 0x04000008
	PROVISIONING_MODE_RESPONSE = 0x04800008
)

const (
	UNPROVISION_REQUEST  = 0x04000010
	UNPROVISION_RESPONSE = 0x04800010
)

const (
	PROVISIONING_STATE_REQUEST  = 0x04000011
	PROVISIONING_STATE_RESPONSE = 0x04800011
)

const (
	CODE_VERSIONS_REQUEST  = 0x0400001A
	CODE_VERSIONS_RESPONSE = 0x0480001A
)

const (
	GET_SECURITY_PARAMETERS_REQUEST  = 0x0400001B
	GET_SECURITY_PARAMETERS_RESPONSE = 0x0480001B
)

const (
	GET_MAC_ADDRESSES_REQUEST  = 0x04000025
	GET_MAC_ADDRESSES_RESPONSE = 0x04800025
)

const (
	GENERATE_RNG_SEED_REQUEST  = 0x04000028
	GENERATE_RNG_SEED_RESPONSE = 0x04800028
)

const (
	SET_PROVISIONING_SERVER_OTP_REQUEST  = 0x0400002A
	SET_PROVISIONING_SERVER_OTP_RESPONSE = 0x0480002A
)

const (
	SET_DNS_SUFFIX_REQUEST  = 0x0400002F
	SET_DNS_SUFFIX_RESPONSE = 0x0480002F
)

const (
	ENUMERATE_HASH_HANDLES_REQUEST  = 0x0400002C
	ENUMERATE_HASH_HANDLES_RESPONSE = 0x0480002C
)

const (
	GET_RNG_SEED_STATUS_REQUEST  = 0x0400002E
	GET_RNG_SEED_STATUS_RESPONSE = 0x0480002E
)

const (
	GET_DNS_SUFFIX_LIST_REQUEST  = 0x0400003E
	GET_DNS_SUFFIX_LIST_RESPONSE = 0x0480003E
)

const (
	SET_ENTERPRISE_ACCESS_REQUEST  = 0x0400003F
	SET_ENTERPRISE_ACCESS_RESPONSE = 0x0480003F
)

const (
	OPEN_USER_INITIATED_CONNECTION_REQUEST  = 0x04000044
	OPEN_USER_INITIATED_CONNECTION_RESPONSE = 0x04800044
)

const (
	CLOSE_USER_INITIATED_CONNECTION_REQUEST  = 0x04000045
	CLOSE_USER_INITIATED_CONNECTION_RESPONSE = 0x04800045
)

const (
	GET_REMOTE_ACCESS_CONNECTION_STATUS_REQUEST  = 0x04000046
	GET_REMOTE_ACCESS_CONNECTION_STATUS_RESPONSE = 0x04800046
)

const (
	GET_CURRENT_POWER_POLICY_REQUEST  = 0x04000047
	GET_CURRENT_POWER_POLICY_RESPONSE = 0x04800047
)

const (
	GET_LAN_INTERFACE_SETTINGS_REQUEST  = 0x04000048
	GET_LAN_INTERFACE_SETTINGS_RESPONSE = 0x04800048
)

const (
	GET_FEATURES_STATE_REQUEST  = 0x04000049
	GET_FEATURES_STATE_RESPONSE = 0x04800049
)

const (
	GET_LAST_HOST_RESET_REASON_REQUEST  = 0x0400004A
	GET_LAST_HOST_RESET_REASON_RESPONSE = 0x0480004A
)

const (
	GET_AMT_STATE_REQUEST  = 0x01000001
	GET_AMT_STATE_RESPONSE = 0x01800001
)

const (
	GET_ZERO_TOUCH_ENABLED_REQUEST  = 0x04000030
	GET_ZERO_TOUCH_ENABLED_RESPONSE = 0x04800030
)

const (
	GET_PROVISIONING_TLS_MODE_REQUEST  = 0x0400002B
	GET_PROVISIONING_TLS_MODE_RESPONSE = 0x0480002B
)

const (
	START_CONFIGURATION_REQUEST  = 0x04000029
	START_CONFIGURATION_RESPONSE = 0x04800029
)

const (
	GET_CERTHASH_ENTRY_REQUEST  = 0x0400002D
	GET_CERTHASH_ENTRY_RESPONSE = 0x0480002D
)

const (
	GET_PKI_FQDN_SUFFIX_REQUEST  = 0x04000036
	GET_PKI_FQDN_SUFFIX_RESPONSE = 0x04800036
)

const (
	SET_HOST_FQDN_REQUEST  = 0x0400005b
	SET_HOST_FQDN_RESPONSE = 0x0480005b
)

const (
	GET_FQDN_REQUEST  = 0x4000056
	GET_FQDN_RESPONSE = 0x4800056
)

const (
	GET_LOCAL_SYSTEM_ACCOUNT_REQUEST  = 0x04000067
	GET_LOCAL_SYSTEM_ACCOUNT_RESPONSE = 0x04800067
)

const (
	GET_EHBC_STATE_REQUEST  = 0x4000084
	GET_EHBC_STATE_RESPONSE = 0x4800084
)

const (
	GET_CONTROL_MODE_REQUEST  = 0x400006b
	GET_CONTROL_MODE_RESPONSE = 0x480006b
)

const (
	STOP_CONFIGURATION_REQUEST  = 0x400005e
	STOP_CONFIGURATION_RESPONSE = 0x480005e
)

const (
	GET_UUID_REQUEST  = 0x400005c
	GET_UUID_RESPONSE = 0x480005c
)

const (
	STATE_INDEPENNDENCE_IsChangeToAMTEnabled_CMD    = 0x5
	STATE_INDEPENNDENCE_IsChangeToAMTEnabled_SUBCMD = 0x51
)

const (
	START_CONFIGURATION_HBASED_REQUEST  = 0x400008b
	START_CONFIGURATION_HBASED_RESPONSE = 0x480008b
)

type AMTUnicodeString struct {
	Length uint16
	String [UNICODE_STRING_LEN]uint8
}
type AMTVersionType struct {
	Description AMTUnicodeString
	Version     AMTUnicodeString
}

type Version struct {
	MajorNumber uint8
	MinorNumber uint8
}
type CodeVersions struct {
	BiosVersion   [BIOS_VERSION_LEN]uint8
	VersionsCount uint32
	Versions      [VERSIONS_NUMBER]AMTVersionType
}

type CommandFormat struct {
	val uint32
	// fields [3]uint32
}
type MessageHeader struct {
	Version  Version
	Reserved uint16
	Command  CommandFormat
	Length   uint32
}
type ResponseMessageHeader struct {
	Header MessageHeader
	Status Status
}
type GetCodeVersionsResponse struct {
	Header      ResponseMessageHeader
	CodeVersion CodeVersions
}

type GetPKIFQDNSuffixResponse struct {
	Header ResponseMessageHeader
	Suffix AMTANSIString
}
type AMTANSIString struct {
	Length uint16
	Buffer [1000]uint8
}

// GetRequest is used for the following requests:
// GetPKIFQDNSuffixRequest
// GetControlModeRequest
// GetUUIDRequest
// GetHashHandlesRequest
// GetRemoteAccessConnectionStatusRequest
type GetRequest struct {
	Header MessageHeader
}
type GetUUIDResponse struct {
	Header ResponseMessageHeader
	UUID   [16]uint8
}

type GetControlModeResponse struct {
	Header ResponseMessageHeader
	State  uint32
}

type UnprovisionRequest struct {
	Header MessageHeader
	Mode   uint32
}

type UnprovisionResponse struct {
	Header ResponseMessageHeader
	State  uint32
}

type LocalSystemAccount struct {
	Username [CFG_MAX_ACL_USER_LENGTH]uint8
	Password [CFG_MAX_ACL_USER_LENGTH]uint8
}

type GetLocalSystemAccountRequest struct {
	Header   MessageHeader
	Reserved [40]uint8
}
type GetLocalSystemAccountResponse struct {
	Header  ResponseMessageHeader
	Account LocalSystemAccount
}
type GetLANInterfaceSettingsRequest struct {
	Header         MessageHeader
	InterfaceIndex uint32
}
type GetLANInterfaceSettingsResponse struct {
	Header      ResponseMessageHeader
	Enabled     uint32
	Ipv4Address uint32
	DhcpEnabled uint32
	DhcpIpMode  uint8
	LinkStatus  uint8
	MacAddress  [6]uint8
}

type AMTHashHandles struct {
	Length  uint32
	Handles [CERT_HASH_MAX_NUMBER]uint32
}
type CertHashEntry struct {
	IsDefault       uint32
	IsActive        uint32
	CertificateHash [CERT_HASH_MAX_LENGTH]uint8
	HashAlgorithm   uint8
	Name            AMTANSIString
}

type GetHashHandlesResponse struct {
	Header      ResponseMessageHeader
	HashHandles AMTHashHandles
}

type GetCertHashEntryRequest struct {
	Header     MessageHeader
	HashHandle uint32
}

type GetCertHashEntryResponse struct {
	Header ResponseMessageHeader
	Hash   CertHashEntry
}

type GetRemoteAccessConnectionStatusResponse struct {
	Header        ResponseMessageHeader
	NetworkStatus uint32
	RemoteStatus  uint32
	RemoteTrigger uint32
	MPSHostname   AMTANSIString
}

type GetStateIndependenceIsChangeToAMTEnabledRequest struct {
	Command       uint8
	ByteCount     uint8
	SubCommand    uint8
	VersionNumber uint8
}

type GetStateIndependenceIsChangeToAMTEnabledResponse struct {
	Enabled uint8
}

type AMTOperationalState uint8

const (
	AmtDisabled = AMTOperationalState(0)
	AmtEnabled  = AMTOperationalState(1)
)

func (opstate AMTOperationalState) String() string {
	if opstate == 0 {
		return "disabled"
	}

	if opstate == 1 {
		return "enabled"
	}

	return ""
}

type SetAmtOperationalState struct {
	Command       uint8
	ByteCount     uint8
	SubCommand    uint8
	VersionNumber uint8
	Enabled       AMTOperationalState
}

type SetAmtOperationalStateResponse struct {
	Command       uint8
	ByteCount     uint8
	SubCommand    uint8
	VersionNumber uint8
	Status        Status
}

type StartConfigurationHBasedRequest struct {
	Header               MessageHeader
	ServerHashAlgorithm  uint8
	ServerCertHash       [CERT_HASH_MAX_LENGTH]uint8
	HostVPNEnable        bool
	SuffixListLen        uint32                                      // max 320
	NetworkDNSSuffixList [MAX_SUFFIX_LENGTH * MAX_DNS_SUFFIXES]uint8 // separated by NULL termination (0x00)
}

type StartConfigurationHBasedResponse struct {
	Header        ResponseMessageHeader
	Status        uint8
	HashAlgorithm uint8
	AMTCertHash   [CERT_HASH_MAX_LENGTH]uint8
}

const (
	CERT_HASH_ALGORITHM_MD5 uint8 = iota
	CERT_HASH_ALGORITHM_SHA1
	CERT_HASH_ALGORITHM_SHA256
	CERT_HASH_ALGORITHM_SHA384
	CERT_HASH_ALGORITHM_SHA224
	CERT_HASH_ALGORITHM_SHA512
)

type StopConfigurationRequest struct {
	Header MessageHeader
}

type StopConfigurationResponse struct {
	Header ResponseMessageHeader
}
