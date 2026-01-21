/*********************************************************************
 * Copyright (c) Intel Corporation 2021
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/
package amt

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/device-management-toolkit/rpc-go/v2/pkg/hotham"
	"github.com/device-management-toolkit/rpc-go/v2/pkg/pthi"
	"github.com/device-management-toolkit/rpc-go/v2/pkg/utils"
	log "github.com/sirupsen/logrus"
)

// TODO: Ensure pointers are freed properly throughout this file

// AMTUnicodeString ...
type AMTUnicodeString struct {
	Length uint16
	String [20]uint8 //[UNICODE_STRING_LEN]
}

// AMTVersionType ...
type AMTVersionType struct {
	Description AMTUnicodeString
	Version     AMTUnicodeString
}

// CodeVersions ...
type CodeVersions struct {
	BiosVersion   [65]uint8 //[BIOS_VERSION_LEN]
	VersionsCount uint32
	Versions      [50]AMTVersionType //[VERSIONS_NUMBER]
}

// InterfaceSettings ...
type InterfaceSettings struct {
	IsEnabled   bool   `json:"isEnable"`
	LinkStatus  string `json:"linkStatus"`
	DHCPEnabled bool   `json:"dhcpEnabled"`
	DHCPMode    string `json:"dhcpMode"`
	IPAddress   string `json:"ipAddress"` // net.IP
	OsIPAddress string `json:"osIpAddress"`
	MACAddress  string `json:"macAddress"`
}

// RemoteAccessStatus holds connect status information
type RemoteAccessStatus struct {
	NetworkStatus string `json:"networkStatus"`
	RemoteStatus  string `json:"remoteStatus"`
	RemoteTrigger string `json:"remoteTrigger"`
	MPSHostname   string `json:"mpsHostname"`
}

// CertHashEntry is the GO struct for holding Cert Hash Entries
type CertHashEntry struct {
	Hash      string
	Name      string
	Algorithm string
	IsActive  bool
	IsDefault bool
}

type SecureHBasedParameters struct {
	CertAlgorithm uint8
	CertHash      [64]byte
}

type SecureHBasedResponse struct {
	Status        string `json:"status"`
	HashAlgorithm string `json:"hashAlgorithm"`
	AMTCertHash   string `json:"amtCertHash"`
}

type StopConfigurationResponse struct {
	Status string `json:"status"`
}

var HashAlgorithmToString = map[uint8]string{
	0: "MD5",
	1: "SHA1",
	2: "SHA256",
	3: "SHA384",
	4: "SHA224",
	5: "SHA512",
}

// LocalSystemAccount holds username and password
type LocalSystemAccount struct {
	Username string
	Password string
}

type ChangeEnabledResponse uint8

const (
	changeEnabledTransitionAllowedMask uint8 = 0x01
	changeEnabledAMTEnabledMask        uint8 = 0x02
	changeEnabledRestrictedMask        uint8 = 0x20
	changeEnabledTlsEnforcedMask       uint8 = 0x40
	changeEnabledNewInterfaceMask      uint8 = 0x80
	changeEnabledTlsAndNewMask         uint8 = 0xC0
	changeEnabledLockedMask            uint8 = 0xE0
)

func (r ChangeEnabledResponse) IsTransitionAllowed() bool {
	return (uint8(r) & changeEnabledTransitionAllowedMask) == changeEnabledTransitionAllowedMask
}

// IsEnabledFlagSet indicates whether the Enabled bit (bit 0) is set.
func (r ChangeEnabledResponse) IsEnabledFlagSet() bool {
	return (uint8(r) & changeEnabledTransitionAllowedMask) == changeEnabledTransitionAllowedMask
}

func (r ChangeEnabledResponse) IsAMTEnabled() bool {
	return (uint8(r) & changeEnabledAMTEnabledMask) == changeEnabledAMTEnabledMask
}

// IsCurrentOperationalStateEnabled indicates whether the CurrentOperationalState bit (bit 1) is set.
func (r ChangeEnabledResponse) IsCurrentOperationalStateEnabled() bool {
	return (uint8(r) & changeEnabledAMTEnabledMask) == changeEnabledAMTEnabledMask
}

func (r ChangeEnabledResponse) IsNewInterfaceVersion() bool {
	return (uint8(r) & changeEnabledNewInterfaceMask) == changeEnabledNewInterfaceMask
}

// SupportsSetAmtOperationalState checks if AMT version supports SetAmtOperationalState command (ME 16.1+)
func (r ChangeEnabledResponse) SupportsSetAmtOperationalState() bool {
	return r.IsNewInterfaceVersion() // Bit 7 indicates ME 16.1+ interface support
}

func (r ChangeEnabledResponse) IsTlsEnforcedOnLocalPorts() bool {
	return (uint8(r) & changeEnabledTlsEnforcedMask) == changeEnabledTlsEnforcedMask
}

// GetTransitionBlockedReason provides specific reason why transition is blocked
func (r ChangeEnabledResponse) GetTransitionBlockedReason() string {
	if r.IsTransitionAllowed() {
		return "Transition is allowed"
	}

	// Decode specific bits to determine exact reason
	rawValue := uint8(r)

	// Bit analysis for blocked transitions
	switch {
	case (rawValue & changeEnabledLockedMask) == changeEnabledLockedMask:
		// bits 7,6,5 set = New+TLS+Restricted, disabled, locked
		return "Device is in locked state - requires unprovisioning first"
	case (rawValue & changeEnabledTlsAndNewMask) == changeEnabledTlsAndNewMask:
		// bits 7,6 set = New+TLS, but transition blocked
		return "Device has TLS enforced and is likely provisioned; requires unprovisioning first"
	case !r.SupportsSetAmtOperationalState():
		return "AMT version does not support operational state transitions"
	case (rawValue & changeEnabledRestrictedMask) != 0:
		// Bit 5 set indicates additional restrictions
		return "Device has additional security restrictions or OEM policy lockdown"
	default:
		// Default case for other blocked scenarios
		return "Device is provisioned or has manufacturer restrictions"
	}
}

type Interface interface {
	Initialize() error
	GetChangeEnabled() (ChangeEnabledResponse, error)
	EnableAMT() error
	DisableAMT() error
	GetVersionDataFromME(key string, amtTimeout time.Duration) (string, error)
	GetUUID() (string, error)
	GetControlMode() (int, error)
	GetProvisioningState() (int, error)
	GetOSDNSSuffix() (string, error)
	GetDNSSuffix() (string, error)
	GetCertificateHashes() ([]CertHashEntry, error)
	GetRemoteAccessConnectionStatus() (RemoteAccessStatus, error)
	GetLANInterfaceSettings(useWireless bool) (InterfaceSettings, error)
	GetLocalSystemAccount() (LocalSystemAccount, error)
	Unprovision() (mode int, err error)
	StartConfigurationHBased(params SecureHBasedParameters) (SecureHBasedResponse, error)
	GetFlog() ([]byte, error)
	StopConfiguration() (StopConfigurationResponse, error)
	GetCiraLog() (pthi.GetCiraLogResponse, error)
}

func ANSI2String(ansi pthi.AMTANSIString) string {
	output := ""
	for i := 0; i < int(ansi.Length); i++ {
		output = output + string(ansi.Buffer[i])
	}

	return output
}

type AMTCommand struct {
	PTHI   pthi.Interface
	HOTHAM hotham.Interface
}

func NewAMTCommand() AMTCommand {
	return AMTCommand{
		PTHI:   pthi.NewCommand(),
		HOTHAM: hotham.NewCommand(),
	}
}

// Initialize determines if rpc is able to initialize the heci driver
func (amt AMTCommand) Initialize() error {
	// initialize HECI interface
	err := amt.PTHI.Open(false)
	if err != nil {
		if err.Error() == "The handle is invalid." {
			return utils.HECIDriverNotDetected //, errors.New("AMT not found: MEI/driver is missing or the call to the HECI driver failed")
		} else {
			return utils.HECIDriverNotDetected //, errors.New("unable to initialize")
		}
	}

	defer amt.PTHI.Close()

	return nil
}

// GetVersionDataFromME ...
func (amt AMTCommand) GetVersionDataFromME(key string, amtTimeout time.Duration) (string, error) {
	// Open the connection and defer closing it.
	if err := amt.PTHI.Open(false); err != nil {
		return "", err
	}
	defer amt.PTHI.Close()

	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()

	startTime := time.Now()

	result, err := amt.PTHI.GetCodeVersions()
	if err != nil {
		// Retry until there's no error or the timeout is exceeded.
		for range ticker.C {
			result, err = amt.PTHI.GetCodeVersions()
			if err == nil || time.Since(startTime) > amtTimeout {
				break
			}
		}
	}

	if err != nil {
		return "", err
	}

	// Look for the matching version using the provided key.
	for i := 0; i < int(result.CodeVersion.VersionsCount); i++ {
		description := string(result.CodeVersion.Versions[i].Description.String[:result.CodeVersion.Versions[i].Description.Length])
		if description == key {
			version := strings.ReplaceAll(string(result.CodeVersion.Versions[i].Version.String[:]), "\u0000", "")

			return version, nil
		}
	}

	return "", errors.New(key + " Not Found")
}

func (amt AMTCommand) GetChangeEnabled() (ChangeEnabledResponse, error) {
	err := amt.PTHI.OpenWatchdog()
	if err != nil {
		return ChangeEnabledResponse(0), err
	}

	defer amt.PTHI.Close()

	rawVal, err := amt.PTHI.IsChangeToAMTEnabled()
	if err != nil {
		return ChangeEnabledResponse(0), err
	}

	return ChangeEnabledResponse(rawVal), nil
}

func (amt AMTCommand) DisableAMT() error {
	return setAmtOperationalState(pthi.AmtDisabled, amt)
}

func (amt AMTCommand) EnableAMT() error {
	return setAmtOperationalState(pthi.AmtEnabled, amt)
}

func setAmtOperationalState(state pthi.AMTOperationalState, amt AMTCommand) error {
	err := amt.PTHI.OpenWatchdog()
	if err != nil {
		return err
	}

	defer amt.PTHI.Close()

	status, err := amt.PTHI.SetAmtOperationalState(state)
	if err != nil {
		return err
	}

	if status != pthi.AMT_STATUS_SUCCESS {
		s := fmt.Sprintf("error setting AMT operational state %s: %s", state, status)

		return errors.New(s)
	}

	return nil
}

// GetUUID ...
func (amt AMTCommand) GetUUID() (string, error) {
	err := amt.PTHI.Open(false)
	if err != nil {
		return "", err
	}

	defer amt.PTHI.Close()

	result, err := amt.PTHI.GetUUID()
	if err != nil {
		return "", err
	}

	var hexValues [16]string

	for i := 0; i < 16; i++ {
		hexValues[i] = fmt.Sprintf("%02x", int(result[i]))
	}

	uuidStr := hexValues[3] + hexValues[2] + hexValues[1] + hexValues[0] + "-" +
		hexValues[5] + hexValues[4] + "-" +
		hexValues[7] + hexValues[6] + "-" +
		hexValues[8] + hexValues[9] + "-" +
		hexValues[10] + hexValues[11] + hexValues[12] + hexValues[13] + hexValues[14] + hexValues[15]

	return uuidStr, nil
}

// GetControlMode ...
func (amt AMTCommand) GetControlMode() (int, error) {
	err := amt.PTHI.Open(false)
	if err != nil {
		return -1, err
	}

	defer amt.PTHI.Close()

	result, err := amt.PTHI.GetControlMode()
	if err != nil {
		return -1, err
	}

	return result, nil
}

// GetProvisioningState ...
func (amt AMTCommand) GetProvisioningState() (int, error) {
	err := amt.PTHI.Open(false)
	if err != nil {
		return -1, err
	}

	defer amt.PTHI.Close()

	result, err := amt.PTHI.GetProvisioningState()
	if err != nil {
		return -1, err
	}

	return result, nil
}

// Unprovision ...
func (amt AMTCommand) Unprovision() (int, error) {
	err := amt.PTHI.Open(false)
	if err != nil {
		return -1, err
	}

	defer amt.PTHI.Close()

	result, err := amt.PTHI.Unprovision()
	if err != nil {
		return -1, err
	}

	return result, nil
}

func (amt AMTCommand) GetDNSSuffix() (string, error) {
	err := amt.PTHI.Open(false)
	if err != nil {
		return "", err
	}

	defer amt.PTHI.Close()

	result, err := amt.PTHI.GetDNSSuffix()
	if err != nil {
		return "", err
	}

	return result, nil
}

func (amt AMTCommand) GetCertificateHashes() ([]CertHashEntry, error) {
	err := amt.PTHI.Open(false)
	amtEntryList := []CertHashEntry{}

	if err != nil {
		return amtEntryList, err
	}

	defer amt.PTHI.Close()

	pthiEntryList, err := amt.PTHI.GetCertificateHashes(pthi.AMTHashHandles{})
	if err != nil {
		return amtEntryList, err
	}

	// Convert pthi results to amt results
	for _, pthiEntry := range pthiEntryList {
		hashSize, algo := utils.InterpretHashAlgorithm(int(pthiEntry.HashAlgorithm))

		hashString := ""
		for i := 0; i < hashSize; i++ {
			hashString = hashString + fmt.Sprintf("%02x", int(pthiEntry.CertificateHash[i]))
		}

		amtEntry := CertHashEntry{
			Hash:      hashString,
			Name:      ANSI2String(pthiEntry.Name),
			Algorithm: algo,
			IsActive:  pthiEntry.IsActive > 0,
			IsDefault: pthiEntry.IsDefault > 0,
		}

		amtEntryList = append(amtEntryList, amtEntry)
	}

	return amtEntryList, nil
}

func (amt AMTCommand) GetRemoteAccessConnectionStatus() (RemoteAccessStatus, error) {
	err := amt.PTHI.Open(false)
	emptyRAStatus := RemoteAccessStatus{}

	if err != nil {
		return emptyRAStatus, err
	}

	defer amt.PTHI.Close()

	result, err := amt.PTHI.GetRemoteAccessConnectionStatus()
	if err != nil {
		return emptyRAStatus, err
	}

	RAStatus := RemoteAccessStatus{
		NetworkStatus: utils.InterpretAMTNetworkConnectionStatus(int(result.NetworkStatus)),
		RemoteStatus:  utils.InterpretRemoteAccessConnectionStatus(int(result.RemoteStatus)),
		RemoteTrigger: utils.InterpretRemoteAccessTrigger(int(result.RemoteTrigger)),
		MPSHostname:   ANSI2String(result.MPSHostname),
	}

	return RAStatus, nil
}

func (amt AMTCommand) GetLANInterfaceSettings(useWireless bool) (InterfaceSettings, error) {
	err := amt.PTHI.Open(false)
	emptySettings := InterfaceSettings{}

	if err != nil {
		return emptySettings, err
	}

	defer amt.PTHI.Close()

	result, err := amt.PTHI.GetLANInterfaceSettings(useWireless)
	if err != nil {
		return emptySettings, err
	}

	settings := InterfaceSettings{
		IPAddress:   "0.0.0.0",
		OsIPAddress: "0.0.0.0",
		IsEnabled:   result.Enabled == 1,
		DHCPEnabled: result.DhcpEnabled == 1,
		LinkStatus:  "down",
		DHCPMode:    "passive",
	}

	if result.LinkStatus == 1 {
		settings.LinkStatus = "up"
	}

	if result.DhcpIpMode == 1 {
		settings.DHCPMode = "active"
	}

	part1 := result.Ipv4Address >> 24 & 0xff
	part2 := result.Ipv4Address >> 16 & 0xff
	part3 := result.Ipv4Address >> 8 & 0xff
	part4 := result.Ipv4Address & 0xff

	settings.IPAddress = strconv.Itoa(int(part1)) + "." + strconv.Itoa(int(part2)) + "." + strconv.Itoa(int(part3)) + "." + strconv.Itoa(int(part4))

	macPart0 := fmt.Sprintf("%02x", int(result.MacAddress[0]))
	macPart1 := fmt.Sprintf("%02x", int(result.MacAddress[1]))
	macPart2 := fmt.Sprintf("%02x", int(result.MacAddress[2]))
	macPart3 := fmt.Sprintf("%02x", int(result.MacAddress[3]))
	macPart4 := fmt.Sprintf("%02x", int(result.MacAddress[4]))
	macPart5 := fmt.Sprintf("%02x", int(result.MacAddress[5]))
	settings.MACAddress = macPart0 + ":" + macPart1 + ":" + macPart2 + ":" + macPart3 + ":" + macPart4 + ":" + macPart5

	return settings, nil
}

func (amt AMTCommand) GetLocalSystemAccount() (LocalSystemAccount, error) {
	err := amt.PTHI.Open(false)
	emptySystemAccount := LocalSystemAccount{}

	if err != nil {
		return emptySystemAccount, err
	}

	defer amt.PTHI.Close()

	result, err := amt.PTHI.GetLocalSystemAccount()
	if err != nil {
		return emptySystemAccount, err
	}

	username := ""

	for i := 0; i < len(result.Account.Username); i++ {
		if string(result.Account.Username[i]) != "\x00" {
			username = username + string(result.Account.Username[i])
		}
	}

	password := ""

	for i := 0; i < len(result.Account.Password); i++ {
		if string(result.Account.Password[i]) != "\x00" {
			password = password + string(result.Account.Password[i])
		}
	}

	lsa := LocalSystemAccount{
		Username: username,
		Password: password,
	}

	return lsa, nil
}

func (amt AMTCommand) StartConfigurationHBased(params SecureHBasedParameters) (SecureHBasedResponse, error) {
	emptySecureHBasedResponse := SecureHBasedResponse{}

	err := amt.PTHI.Open(false)
	if err != nil {
		return emptySecureHBasedResponse, err
	}

	defer amt.PTHI.Close()

	result, err := amt.PTHI.StartConfigurationHBased(params.CertAlgorithm, params.CertHash, false, 0, [320]byte{})
	if err != nil {
		return emptySecureHBasedResponse, err
	}

	shbr := SecureHBasedResponse{
		Status:        result.Header.Status.String(),
		HashAlgorithm: HashAlgorithmToString[result.HashAlgorithm],
		AMTCertHash:   string(result.AMTCertHash[:64]),
	}

	return shbr, nil
}

func (amt AMTCommand) StopConfiguration() (response StopConfigurationResponse, err error) {
	err = amt.PTHI.Open(false)
	if err != nil {
		return StopConfigurationResponse{}, err
	}

	defer amt.PTHI.Close()

	result, err := amt.PTHI.StopConfiguration()
	if err != nil {
		return StopConfigurationResponse{}, err
	}

	response = StopConfigurationResponse{
		Status: result.Header.Status.String(),
	}

	return response, nil
}

// GetFlog retrieves the CSME Flash Log (FLOG)
func (amt AMTCommand) GetFlog() ([]byte, error) {
	err := amt.HOTHAM.Open()
	if err != nil {
		log.Errorf("Failed to open HOTHAM interface: %v", err)

		return nil, err
	}

	defer amt.HOTHAM.Close()

	// First try GetFlogSize to check if FLOG is supported
	flogSize, err := amt.HOTHAM.GetFlogSize()
	if err != nil {
		log.Errorf("GetFlogSize failed: %v", err)

		return nil, fmt.Errorf("GetFlogSize failed: %w", err)
	}

	log.Tracef("FLOG size: %d bytes", flogSize)

	// Retrieve the FLOG data
	flogData, err := amt.HOTHAM.GetFlog()
	if err != nil {
		log.Errorf("Failed to get FLOG data: %v", err)

		return nil, err
	}

	log.Debugf("Successfully retrieved %d bytes of FLOG data", len(flogData))

	return flogData, nil
}

func (amt AMTCommand) GetCiraLog() (pthi.GetCiraLogResponse, error) {
	err := amt.PTHI.Open(false)
	if err != nil {
		return pthi.GetCiraLogResponse{}, err
	}

	defer amt.PTHI.Close()

	result, err := amt.PTHI.GetCiraLog()
	if err != nil {
		return pthi.GetCiraLogResponse{}, err
	}

	return result, nil
}
