/*********************************************************************
 * Copyright (c) Intel Corporation 2021
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/

package commands

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/alecthomas/kong"
	"github.com/device-management-toolkit/rpc-go/v2/internal/amt"
	"github.com/device-management-toolkit/rpc-go/v2/internal/config"
	localamt "github.com/device-management-toolkit/rpc-go/v2/internal/local/amt"
	"github.com/device-management-toolkit/rpc-go/v2/pkg/utils"
	log "github.com/sirupsen/logrus"
)

const notFoundIP = "Not Found"

// AmtInfoCmd represents the amtinfo command with Kong CLI binding
type AmtInfoCmd struct {
	// Version information flags
	Ver bool `help:"Show AMT Version" short:"r"`
	Bld bool `help:"Show Build Number" short:"b"`
	Sku bool `help:"Show Product SKU" short:"s"`

	// Identity flags
	UUID bool `help:"Show Unique Identifier" short:"u"`
	Mode bool `help:"Show Current Control Mode" short:"m"`

	// Network flags
	DNS      bool `help:"Show Domain Name Suffix" short:"d"`
	Hostname bool `help:"Show OS Hostname" short:"h"`
	Lan      bool `help:"Show LAN Settings" short:"l"`

	// Status flags
	Ras     bool `help:"Show Remote Access Status" short:"a"`
	OpState bool `help:"Show AMT Operational State" name:"operationalState"`

	// Certificate flags
	Cert     bool   `help:"Show System Certificate Hashes" short:"c"`
	UserCert bool   `help:"Show User Certificates only (AMT password required)" name:"userCert"`
	Password string `help:"AMT Password" env:"AMT_PASSWORD" short:"p"`

	// Special flags
	All bool `help:"Show All AMT Information" short:"A"`
}

// Validate implements Kong's extensible validation interface for business logic validation
func (cmd *AmtInfoCmd) Validate(kctx *kong.Context, amtCommand amt.Interface) error {
	// Handle interactive password prompting for user certificates
	if cmd.IsUserCertRequested() && cmd.Password == "" {
		// Check if device is provisioned before prompting for password
		controlMode, err := amtCommand.GetControlMode()
		if err != nil {
			return fmt.Errorf("failed to get control mode for userCert validation: %w", err)
		}

		if controlMode == 0 {
			return fmt.Errorf("device is in pre-provisioning mode. User certificates are not available until device is provisioned")
		}

		// Prompt for password interactively
		if utils.PR == nil {
			return fmt.Errorf("password is required for user certificate operations but no password reader available")
		}

		fmt.Printf("Please enter AMT Password (required for user certificates): ")

		password, err := utils.PR.ReadPassword()
		if err != nil {
			return fmt.Errorf("failed to read password: %w", err)
		}

		if password == "" {
			return fmt.Errorf("password is required for user certificate operations")
		}

		// Trim any newline characters that might come from non-terminal input
		if len(password) > 0 && password[len(password)-1] == '\n' {
			password = password[:len(password)-1]
		}

		cmd.Password = password
	}

	return nil
}

// IsUserCertRequested checks if user certificates are requested
func (cmd *AmtInfoCmd) IsUserCertRequested() bool {
	return cmd.UserCert || cmd.All
}

// HasNoFlagsSet checks if no specific flags are set (meaning show all)
func (cmd *AmtInfoCmd) HasNoFlagsSet() bool {
	return !cmd.Ver && !cmd.Bld && !cmd.Sku && !cmd.UUID && !cmd.Mode && !cmd.DNS &&
		!cmd.Cert && !cmd.UserCert && !cmd.Ras && !cmd.Lan && !cmd.Hostname && !cmd.OpState
}

// Run executes the amtinfo command
func (cmd *AmtInfoCmd) Run(ctx *Context) error {
	service := NewInfoService(ctx.AMTCommand)
	service.jsonOutput = ctx.JsonOutput
	service.password = cmd.Password
	service.localTLSEnforced = ctx.LocalTLSEnforced
	service.skipCertCheck = ctx.SkipCertCheck

	result, err := service.GetAMTInfo(cmd)
	if err != nil {
		return err
	}

	if ctx.JsonOutput {
		return service.OutputJSON(result)
	}

	return service.OutputText(result, cmd)
}

// Context holds shared dependencies injected into commands
type Context struct {
	AMTCommand       amt.Interface
	LogLevel         string
	JsonOutput       bool
	Verbose          bool
	LocalTLSEnforced bool
	SkipCertCheck    bool
}

// InfoResult holds the complete AMT information result
type InfoResult struct {
	AMT               string                       `json:"amt,omitempty"`
	BuildNumber       string                       `json:"buildNumber,omitempty"`
	SKU               string                       `json:"sku,omitempty"`
	Features          string                       `json:"features,omitempty"`
	UUID              string                       `json:"uuid,omitempty"`
	ControlMode       string                       `json:"controlMode,omitempty"`
	OperationalState  string                       `json:"operationalState,omitempty"`
	DNSSuffix         string                       `json:"dnsSuffix,omitempty"`
	DNSSuffixOS       string                       `json:"dnsSuffixOS,omitempty"`
	HostnameOS        string                       `json:"hostnameOS,omitempty"`
	RAS               *amt.RemoteAccessStatus      `json:"ras,omitempty"`
	WiredAdapter      *amt.InterfaceSettings       `json:"wiredAdapter,omitempty"`
	WirelessAdapter   *amt.InterfaceSettings       `json:"wirelessAdapter,omitempty"`
	CertificateHashes map[string]amt.CertHashEntry `json:"certificateHashes,omitempty"`
	UserCerts         map[string]UserCert          `json:"userCerts,omitempty"`
}

// UserCert represents a user certificate
type UserCert struct {
	Subject                string `json:"subject,omitempty"`
	Issuer                 string `json:"issuer,omitempty"`
	TrustedRootCertificate bool   `json:"trustedRootCertificate,omitempty"`
	ReadOnlyCertificate    bool   `json:"readOnlyCertificate,omitempty"`
}

// InfoService provides methods for retrieving and displaying AMT information
type InfoService struct {
	amtCommand       amt.Interface
	jsonOutput       bool
	password         string
	localTLSEnforced bool
	skipCertCheck    bool
}

// NewInfoService creates a new InfoService with the given AMT command
func NewInfoService(amtCommand amt.Interface) *InfoService {
	return &InfoService{
		amtCommand:       amtCommand,
		jsonOutput:       false,
		password:         "",
		localTLSEnforced: false,
		skipCertCheck:    false,
	}
}

// GetAMTInfo retrieves AMT information based on the command flags
func (s *InfoService) GetAMTInfo(cmd *AmtInfoCmd) (*InfoResult, error) {
	result := &InfoResult{}
	showAll := cmd.All || s.hasNoFlagsSet(cmd)

	// Track control mode for reuse across multiple operations
	var controlMode = -1 // -1 indicates not checked yet

	var controlModeErr error

	// Get AMT version information
	if showAll || cmd.Ver {
		version, err := s.amtCommand.GetVersionDataFromME("AMT", 2*time.Minute)
		if err != nil {
			log.Error("Failed to get AMT version: ", err)
		} else {
			result.AMT = version
		}
	}

	// Get build number
	if showAll || cmd.Bld {
		build, err := s.amtCommand.GetVersionDataFromME("Build Number", 2*time.Minute)
		if err != nil {
			log.Error("Failed to get build number: ", err)
		} else {
			result.BuildNumber = build
		}
	}

	// Get SKU
	if showAll || cmd.Sku {
		sku, err := s.amtCommand.GetVersionDataFromME("Sku", 2*time.Minute)
		if err != nil {
			log.Error("Failed to get SKU: ", err)
		} else {
			result.SKU = sku
		}
	}

	// Decode AMT features if we have both version and SKU and both flags are set
	if (showAll || (cmd.Ver && cmd.Sku)) && result.AMT != "" && result.SKU != "" {
		result.Features = strings.TrimSpace(utils.DecodeAMTFeatures(result.AMT, result.SKU))
	}

	// Get UUID
	if showAll || cmd.UUID {
		uuid, err := s.amtCommand.GetUUID()
		if err != nil {
			log.Error("Failed to get UUID: ", err)
		} else {
			result.UUID = uuid
		}
	}

	// Get control mode
	if showAll || cmd.Mode {
		// Use cached control mode if already retrieved, otherwise get it
		if controlMode == -1 {
			controlMode, controlModeErr = s.amtCommand.GetControlMode()
		}

		if controlModeErr != nil {
			log.Error("Failed to get control mode: ", controlModeErr)
		} else {
			result.ControlMode = utils.InterpretControlMode(controlMode)
		}
	}

	// Get operational state (for AMT versions > 11)
	if showAll || cmd.OpState {
		// We need AMT version to check if we can get operational state
		if result.AMT == "" {
			version, err := s.amtCommand.GetVersionDataFromME("AMT", 2*time.Minute)
			if err == nil {
				result.AMT = version
			}
		}

		if result.AMT != "" {
			majorVersion, err := s.getMajorVersion(result.AMT)
			if err == nil && majorVersion > 11 {
				opState, err := s.amtCommand.GetChangeEnabled()
				if err == nil && opState.IsNewInterfaceVersion() {
					if opState.IsAMTEnabled() {
						result.OperationalState = "enabled"
					} else {
						result.OperationalState = "disabled"
					}
				}
			} else if err == nil {
				log.Debug("OpState will not work on AMT versions 11 and below.")
			}
		}
	}

	// Get DNS information
	if showAll || cmd.DNS {
		dnsSuffix, err := s.amtCommand.GetDNSSuffix()
		if err == nil {
			result.DNSSuffix = dnsSuffix
		}

		osDnsSuffix, err := s.amtCommand.GetOSDNSSuffix()
		if err == nil {
			result.DNSSuffixOS = osDnsSuffix
		}
	}

	// Get hostname from OS
	if showAll || cmd.Hostname {
		hostname, err := os.Hostname()
		if err == nil {
			result.HostnameOS = hostname
		}
	}

	// Get RAS (Remote Access Status)
	if showAll || cmd.Ras {
		ras, err := s.amtCommand.GetRemoteAccessConnectionStatus()
		if err == nil {
			result.RAS = &ras
		}
	}

	// Get LAN interface settings
	if showAll || cmd.Lan {
		wired, err := s.amtCommand.GetLANInterfaceSettings(false)
		if err == nil {
			wired.OsIPAddress = s.getOSIPAddress(wired.MACAddress)
			result.WiredAdapter = &wired
		}

		wireless, err := s.amtCommand.GetLANInterfaceSettings(true)
		if err == nil {
			wireless.OsIPAddress = s.getOSIPAddress(wireless.MACAddress)
			result.WirelessAdapter = &wireless
		}
	}

	// Get certificate hashes
	if showAll || cmd.Cert {
		certResult, err := s.amtCommand.GetCertificateHashes()
		if err == nil {
			result.CertificateHashes = make(map[string]amt.CertHashEntry)
			for _, cert := range certResult {
				result.CertificateHashes[cert.Name] = cert
			}
		}
	}

	// Get user certificates (requires WSMAN client setup)
	if showAll || cmd.UserCert {
		// Get control mode if not already retrieved
		if controlMode == -1 {
			controlMode, _ = s.amtCommand.GetControlMode()
		}

		if s.password != "" {
			userCerts, err := s.getUserCertificates(controlMode)
			if err != nil {
				log.Error("Failed to get user certificates: ", err)
			} else {
				result.UserCerts = userCerts
			}
		}
	}

	return result, nil
}

// OutputJSON outputs the result in JSON format
func (s *InfoService) OutputJSON(result *InfoResult) error {
	jsonBytes, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal JSON: %w", err)
	}

	fmt.Println(string(jsonBytes))

	return nil
}

// OutputText outputs the result in human-readable text format
func (s *InfoService) OutputText(result *InfoResult, cmd *AmtInfoCmd) error {
	showAll := cmd.All || s.hasNoFlagsSet(cmd)

	if (showAll || cmd.Ver) && result.AMT != "" {
		fmt.Printf("Version\t\t\t: %s\n", result.AMT)
	}

	if (showAll || cmd.Bld) && result.BuildNumber != "" {
		fmt.Printf("Build Number\t\t: %s\n", result.BuildNumber)
	}

	if (showAll || cmd.Sku) && result.SKU != "" {
		fmt.Printf("SKU\t\t\t: %s\n", result.SKU)
	}

	if (showAll || (cmd.Ver && cmd.Sku)) && result.Features != "" {
		fmt.Printf("Features\t\t: %s\n", result.Features)
	}

	if (showAll || cmd.UUID) && result.UUID != "" {
		fmt.Printf("UUID\t\t\t: %s\n", result.UUID)
	}

	if (showAll || cmd.Mode) && result.ControlMode != "" {
		fmt.Printf("Control Mode\t\t: %s\n", result.ControlMode)
	}

	if (showAll || cmd.OpState) && result.OperationalState != "" {
		fmt.Printf("Operational State\t: %s\n", result.OperationalState)
	}

	if showAll || cmd.DNS {
		fmt.Printf("DNS Suffix\t\t: %s\n", result.DNSSuffix)
		fmt.Printf("DNS Suffix (OS)\t\t: %s\n", result.DNSSuffixOS)
	}

	if (showAll || cmd.Hostname) && result.HostnameOS != "" {
		fmt.Printf("Hostname (OS)\t\t: %s\n", result.HostnameOS)
	}

	// Output RAS information
	if (showAll || cmd.Ras) && result.RAS != nil {
		fmt.Printf("RAS Network\t\t: %s\n", result.RAS.NetworkStatus)
		fmt.Printf("RAS Remote Status\t: %s\n", result.RAS.RemoteStatus)
		fmt.Printf("RAS Trigger\t\t: %s\n", result.RAS.RemoteTrigger)
		fmt.Printf("RAS MPS Hostname\t: %s\n", result.RAS.MPSHostname)
	}

	// Output wired adapter information
	if (showAll || cmd.Lan) && result.WiredAdapter != nil && result.WiredAdapter.MACAddress != "00:00:00:00:00:00" {
		fmt.Println("---Wired Adapter---")
		fmt.Printf("DHCP Enabled\t\t: %s\n", strconv.FormatBool(result.WiredAdapter.DHCPEnabled))
		fmt.Printf("DHCP Mode\t\t: %s\n", result.WiredAdapter.DHCPMode)
		fmt.Printf("Link Status\t\t: %s\n", result.WiredAdapter.LinkStatus)
		fmt.Printf("AMT IP Address\t\t: %s\n", result.WiredAdapter.IPAddress)
		fmt.Printf("OS IP Address\t\t: %s\n", result.WiredAdapter.OsIPAddress)
		fmt.Printf("MAC Address\t\t: %s\n", result.WiredAdapter.MACAddress)
	}

	// Output wireless adapter information
	if (showAll || cmd.Lan) && result.WirelessAdapter != nil {
		fmt.Println("---Wireless Adapter---")
		fmt.Printf("DHCP Enabled\t\t: %s\n", strconv.FormatBool(result.WirelessAdapter.DHCPEnabled))
		fmt.Printf("DHCP Mode\t\t: %s\n", result.WirelessAdapter.DHCPMode)
		fmt.Printf("Link Status\t\t: %s\n", result.WirelessAdapter.LinkStatus)
		fmt.Printf("AMT IP Address\t\t: %s\n", result.WirelessAdapter.IPAddress)
		fmt.Printf("OS IP Address\t\t: %s\n", result.WirelessAdapter.OsIPAddress)
		fmt.Printf("MAC Address\t\t: %s\n", result.WirelessAdapter.MACAddress)
	}

	// Output certificate hashes (system certs)
	if showAll || cmd.Cert {
		if len(result.CertificateHashes) > 0 {
			fmt.Println("---Certificate Hashes---")

			for name, cert := range result.CertificateHashes {
				fmt.Printf("%s", name)

				if cert.IsDefault && cert.IsActive {
					fmt.Printf("  (Default, Active)")
				} else if cert.IsDefault {
					fmt.Printf("  (Default)")
				} else if cert.IsActive {
					fmt.Printf("  (Active)")
				}

				fmt.Println()
				fmt.Printf("   %s: %s\n", cert.Algorithm, cert.Hash)
			}
		} else if cmd.Cert {
			fmt.Println("---No Certificate Hashes Found---")
		}
	}

	// Output user certificates (separate from system certs)
	if showAll || cmd.UserCert {
		if len(result.UserCerts) > 0 {
			fmt.Println("---Public Key Certs---")

			for name, cert := range result.UserCerts {
				fmt.Printf("%s", name)

				if cert.TrustedRootCertificate && cert.ReadOnlyCertificate {
					fmt.Printf("  (TrustedRoot, ReadOnly)")
				} else if cert.TrustedRootCertificate {
					fmt.Printf("  (TrustedRoot)")
				} else if cert.ReadOnlyCertificate {
					fmt.Printf("  (ReadOnly)")
				}

				fmt.Println()
			}
		} else if cmd.UserCert {
			fmt.Println("---No Public Key Certs Found---")
		}
	}

	return nil
}

// hasNoFlagsSet checks if no specific flags are set (meaning show all)
func (s *InfoService) hasNoFlagsSet(cmd *AmtInfoCmd) bool {
	return !cmd.Ver && !cmd.Bld && !cmd.Sku && !cmd.UUID && !cmd.Mode && !cmd.DNS &&
		!cmd.Cert && !cmd.UserCert && !cmd.Ras && !cmd.Lan && !cmd.Hostname && !cmd.OpState
}

// getOSIPAddress gets the OS IP address for a given MAC address
func (s *InfoService) getOSIPAddress(macAddr string) string {
	if macAddr == "00:00:00:00:00:00" {
		return "0.0.0.0"
	}

	// Parse MAC address
	macBytes := make([]byte, 6)
	macParts := strings.Split(macAddr, ":")

	for i, part := range macParts {
		if i >= 6 {
			break
		}

		val, err := strconv.ParseUint(part, 16, 8)
		if err != nil {
			return notFoundIP
		}

		macBytes[i] = uint8(val)
	}

	// Get network interfaces
	interfaces, err := net.Interfaces()
	if err != nil {
		return notFoundIP
	}

	// Find matching interface
	for _, iface := range interfaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}

		// Compare MAC addresses
		if len(iface.HardwareAddr) == 6 {
			match := true

			for i := 0; i < 6; i++ {
				if iface.HardwareAddr[i] != macBytes[i] {
					match = false

					break
				}
			}

			if match {
				addrs, err := iface.Addrs()
				if err != nil {
					continue
				}

				// Find IPv4 address
				for _, addr := range addrs {
					ipNet, ok := addr.(*net.IPNet)
					if ok && !ipNet.IP.IsLoopback() {
						if ipNet.IP.To4() != nil {
							return ipNet.IP.String()
						}
					}
				}
			}
		}
	}

	return notFoundIP
}

// getMajorVersion extracts the major version number from an AMT version string
func (s *InfoService) getMajorVersion(version string) (int, error) {
	parts := strings.Split(version, ".")
	if len(parts) < 1 {
		return 0, fmt.Errorf("invalid AMT version format")
	}

	majorVersion, err := strconv.Atoi(parts[0])
	if err != nil {
		return 0, fmt.Errorf("invalid AMT version: %w", err)
	}

	return majorVersion, nil
}

// GetTokenFromKeyValuePairs extracts a token value from a comma-separated key=value string
func GetTokenFromKeyValuePairs(kvList string, token string) string {
	attributes := strings.Split(kvList, ",")
	tokenMap := make(map[string]string)

	for _, att := range attributes {
		parts := strings.Split(att, "=")
		if len(parts) == 2 {
			tokenMap[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
		}
	}

	return tokenMap[token]
}

// getUserCertificates retrieves public key certificates via WSMAN
func (s *InfoService) getUserCertificates(controlMode int) (map[string]UserCert, error) {
	// Control mode is passed as parameter to avoid duplicate checks
	if controlMode == 0 {
		return nil, fmt.Errorf("device is in pre-provisioning mode, user certificates are not available")
	}

	// Create WSMAN client
	wsmanClient := localamt.NewGoWSMANMessages(utils.LMSAddress)

	// Setup TLS configuration
	var tlsConfig *tls.Config
	if s.localTLSEnforced {
		tlsConfig = config.GetTLSConfig(&controlMode, nil, s.skipCertCheck)
	} else {
		tlsConfig = &tls.Config{InsecureSkipVerify: s.skipCertCheck}
	}

	// Setup WSMAN client with admin credentials
	err := wsmanClient.SetupWsmanClient("admin", s.password, s.localTLSEnforced, log.GetLevel() == log.TraceLevel, tlsConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to setup WSMAN client: %w", err)
	}

	// Get public key certificates
	publicKeyCerts, err := wsmanClient.GetPublicKeyCerts()
	if err != nil {
		return nil, fmt.Errorf("failed to get public key certificates: %w", err)
	}

	// Process certificates into user cert map
	userCertMap := make(map[string]UserCert)

	for _, cert := range publicKeyCerts {
		// Get certificate name from CN in subject, fallback to InstanceID
		name := GetTokenFromKeyValuePairs(cert.Subject, "CN")
		if name == "" {
			name = cert.InstanceID
		}

		userCert := UserCert{
			Subject:                cert.Subject,
			Issuer:                 cert.Issuer,
			TrustedRootCertificate: cert.TrustedRootCertificate,
			ReadOnlyCertificate:    cert.ReadOnlyCertificate,
		}

		userCertMap[name] = userCert
	}

	return userCertMap, nil
}
