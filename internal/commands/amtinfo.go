/*********************************************************************
 * Copyright (c) Intel Corporation 2021
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/

package commands

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	neturl "net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/alecthomas/kong"
	"github.com/device-management-toolkit/rpc-go/v2/internal/certs"
	"github.com/device-management-toolkit/rpc-go/v2/internal/interfaces"
	localamt "github.com/device-management-toolkit/rpc-go/v2/internal/local/amt"
	"github.com/device-management-toolkit/rpc-go/v2/internal/profile"
	"github.com/device-management-toolkit/rpc-go/v2/pkg/amt"
	"github.com/device-management-toolkit/rpc-go/v2/pkg/upid"
	"github.com/device-management-toolkit/rpc-go/v2/pkg/utils"
	log "github.com/sirupsen/logrus"
)

const (
	notFoundIP = "Not Found"
	zeroIP     = "0.0.0.0"
)

// AmtInfoCmd represents the amtinfo command with Kong CLI binding
type AmtInfoCmd struct {
	AMTBaseCmd

	// Version information flags
	Ver bool `help:"Show AMT Version" short:"r"`
	Bld bool `help:"Show Build Number" short:"b"`
	Sku bool `help:"Show Product SKU" short:"s"`

	// Identity flags
	UUID      bool `help:"Show Unique Identifier" short:"u"`
	UPID      bool `help:"Show Intel Unique Platform ID"`
	Mode      bool `help:"Show Current Control Mode" short:"m"`
	ProvState bool `help:"Show Provisioning State" name:"provisioningState" short:"p"`

	// Network flags
	DNS      bool `help:"Show Domain Name Suffix" short:"d"`
	Hostname bool `help:"Show OS Hostname"`
	Lan      bool `help:"Show LAN Settings" short:"l"`

	// Status flags
	Ras     bool `help:"Show Remote Access Status" short:"a"`
	OpState bool `help:"Show AMT Operational State" name:"operationalState"`

	// Certificate flags
	Cert     bool `help:"Show System Certificate Hashes" short:"c"`
	UserCert bool `help:"Show User Certificates only (AMT password required)" name:"userCert"`

	// Special flags
	All bool `help:"Show All AMT Information" short:"A"`

	// Sync to server flags
	Sync bool   `help:"Sync device info to remote server via HTTP PATCH"`
	URL  string `help:"Endpoint URL of the devices API (e.g., https://mps.example.com/api/v1/devices)" name:"url"`
}

// RequiresAMTPassword indicates whether this command requires AMT password.
// amtinfo never requires a password prompt — it uses the Local System Account (LSA) for WSMAN.
func (cmd *AmtInfoCmd) RequiresAMTPassword() bool {
	return false
}

// Validate implements Kong's extensible validation interface for business logic validation
func (cmd *AmtInfoCmd) Validate(kctx *kong.Context) error {
	// amtinfo handles its own WSMAN setup internally via ensureWSMANClient (using LSA).
	cmd.SkipWSMANSetup = true

	log.Trace("Validating amtinfo command")

	// Basic validation for sync mode
	if cmd.Sync {
		if strings.TrimSpace(cmd.URL) == "" {
			return fmt.Errorf("--url is required when --sync is specified")
		}

		if _, err := neturl.ParseRequestURI(cmd.URL); err != nil {
			return fmt.Errorf("invalid --url: %w", err)
		}
		// // Require some form of authentication when syncing
		// if err := cmd.ValidateRequired(true); err != nil {
		// 	return err
		// }
	}

	return nil
}

// HasNoFlagsSet checks if no specific flags are set (meaning show all)
func (cmd *AmtInfoCmd) HasNoFlagsSet() bool {
	return !cmd.Ver && !cmd.Bld && !cmd.Sku && !cmd.UUID && !cmd.UPID && !cmd.Mode && !cmd.ProvState && !cmd.DNS &&
		!cmd.Cert && !cmd.UserCert && !cmd.Ras && !cmd.Lan && !cmd.Hostname && !cmd.OpState
}

// Run executes the amtinfo command
func (cmd *AmtInfoCmd) Run(ctx *Context) error {
	log.Trace("Running amtinfo command")

	service := NewInfoService(ctx.AMTCommand)
	service.jsonOutput = ctx.JsonOutput
	service.password = ctx.AMTPassword
	service.localTLSEnforced = cmd.LocalTLSEnforced
	// Use AMT-specific skip flag for WSMAN/TLS to firmware
	service.skipAMTCertCheck = ctx.SkipAMTCertCheck
	service.wsman = cmd.GetWSManClient()

	// If syncing, ensure we collect full device info regardless of selective flags
	effectiveCmd := cmd
	if cmd.Sync {
		copied := *cmd
		copied.All = true
		effectiveCmd = &copied
	}

	result, err := service.GetAMTInfo(effectiveCmd)
	if err != nil {
		return err
	}

	// If requested, sync device info to remote server
	if cmd.Sync {
		if err := service.SyncDeviceInfo(ctx, result, cmd.URL, &ctx.ServerAuthFlags); err != nil {
			return err
		}
	}

	if ctx.JsonOutput {
		return service.OutputJSON(result)
	}

	return service.OutputText(result, cmd)
}

// InfoResult holds the complete AMT information result
type InfoResult struct {
	AMT               string                       `json:"amt,omitempty"`
	BuildNumber       string                       `json:"buildNumber,omitempty"`
	SKU               string                       `json:"sku,omitempty"`
	Features          string                       `json:"features,omitempty"`
	UUID              string                       `json:"uuid,omitempty"`
	ControlMode       string                       `json:"controlMode,omitempty"`
	ProvisioningState string                       `json:"provisioningState,omitempty"`
	OperationalState  string                       `json:"operationalState,omitempty"`
	DNSSuffix         string                       `json:"dnsSuffix,omitempty"`
	DNSSuffixOS       string                       `json:"dnsSuffixOS,omitempty"`
	HostnameOS        string                       `json:"hostnameOS,omitempty"`
	RAS               *amt.RemoteAccessStatus      `json:"ras,omitempty"`
	WiredAdapter      *amt.InterfaceSettings       `json:"wiredAdapter,omitempty"`
	WirelessAdapter   *amt.InterfaceSettings       `json:"wirelessAdapter,omitempty"`
	UPID              *upid.UPID                   `json:"upid,omitempty"`
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
	// skipAMTCertCheck controls TLS verification when connecting to AMT/LMS
	skipAMTCertCheck bool
	wsman            interfaces.WSMANer
}

// NewInfoService creates a new InfoService with the given AMT command
func NewInfoService(amtCommand amt.Interface) *InfoService {
	return &InfoService{
		amtCommand:       amtCommand,
		jsonOutput:       false,
		password:         "",
		localTLSEnforced: false,
		skipAMTCertCheck: false,
		wsman:            nil,
	}
}

// syncPayload mirrors the expected JSON body for the PATCH request
type syncPayload struct {
	GUID       string         `json:"guid"`
	DeviceInfo syncDeviceInfo `json:"deviceInfo"`
}

type syncDeviceInfo struct {
	FWVersion   string    `json:"fwVersion"`
	FWBuild     string    `json:"fwBuild"`
	FWSku       string    `json:"fwSku"`
	CurrentMode string    `json:"currentMode"`
	Features    string    `json:"features"`
	IPAddress   string    `json:"ipAddress"`
	LastUpdated time.Time `json:"lastUpdated"`
}

// SyncDeviceInfo sends a PATCH to the provided endpoint URL with the device info payload
// The urlArg is expected to be a full URL to the devices endpoint (e.g., https://mps.example.com/api/v1/devices)
func (s *InfoService) SyncDeviceInfo(ctx *Context, result *InfoResult, urlArg string, auth *ServerAuthFlags) error {
	// Use the provided URL directly as the target endpoint
	endpoint := urlArg

	payload := syncPayload{
		GUID: result.UUID,
		DeviceInfo: syncDeviceInfo{
			FWVersion:   result.AMT,
			FWBuild:     result.BuildNumber,
			FWSku:       result.SKU,
			CurrentMode: result.ControlMode,
			Features:    result.Features,
			IPAddress:   bestIPAddress(result),
			LastUpdated: time.Now(),
		},
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal sync payload: %w", err)
	}

	httpClient := &http.Client{Timeout: 10 * time.Second}
	// Respect skip-cert-check for HTTPS endpoints
	if strings.HasPrefix(strings.ToLower(endpoint), "https://") && ctx.SkipCertCheck {
		httpClient.Transport = &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: ctx.SkipCertCheck}}
	}

	// Create a request with context to comply with lint noctx rule and allow cancellation., not to be confused with context of kong cli commands
	reqCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(reqCtx, http.MethodPatch, endpoint, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("failed to create PATCH request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	// Apply Authorization header. If username/password are provided without a token, exchange for a token first.
	if auth != nil {
		token := strings.TrimSpace(auth.AuthToken)
		if token == "" && auth.AuthUsername != "" && auth.AuthPassword != "" {
			// Derive the base (scheme://host) from the target endpoint for default auth endpoints
			parsed, perr := neturl.Parse(endpoint)
			if perr != nil {
				return fmt.Errorf("invalid endpoint url: %w", perr)
			}

			base := fmt.Sprintf("%s://%s", parsed.Scheme, parsed.Host)

			t, aerr := profile.Authenticate(base, auth.AuthUsername, auth.AuthPassword, auth.AuthEndpoint, ctx.SkipCertCheck, 10*time.Second)
			if aerr != nil {
				return fmt.Errorf("authentication failed: %w", aerr)
			}

			token = t
		}

		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("sync request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("sync failed with status %s", resp.Status)
	}

	return nil
}

// bestIPAddress chooses a reasonable IP address for reporting
func bestIPAddress(res *InfoResult) string {
	// Prefer OS IP from wired
	if res.WiredAdapter != nil {
		if ip := strings.TrimSpace(res.WiredAdapter.OsIPAddress); ip != "" && ip != zeroIP && ip != notFoundIP {
			return ip
		}

		if ip := strings.TrimSpace(res.WiredAdapter.IPAddress); ip != "" && ip != zeroIP && ip != notFoundIP {
			return ip
		}
	}

	if res.WirelessAdapter != nil {
		if ip := strings.TrimSpace(res.WirelessAdapter.OsIPAddress); ip != "" && ip != zeroIP && ip != notFoundIP {
			return ip
		}

		if ip := strings.TrimSpace(res.WirelessAdapter.IPAddress); ip != "" && ip != zeroIP && ip != notFoundIP {
			return ip
		}
	}

	return zeroIP
}

// joinURL safely concatenates base URL and path
// (previously had joinURL helper; no longer needed as endpoints are provided in full)

// GetAMTInfo retrieves AMT information based on the command flags
func (s *InfoService) GetAMTInfo(cmd *AmtInfoCmd) (*InfoResult, error) {
	result := &InfoResult{}
	showAll := cmd.All || cmd.HasNoFlagsSet()

	// Track control mode for reuse across multiple operations
	controlMode := -1 // -1 indicates not checked yet

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

	// Get UPID (Intel Unique Platform ID)
	if showAll || cmd.UPID {
		upidData, err := upid.NewClient().GetUPID()
		if err != nil {
			log.Trace("Failed to get UPID: ", err)
		} else if upidData != nil {
			result.UPID = upidData
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

	// Get provisioning state
	if showAll || cmd.ProvState {
		provState, err := s.amtCommand.GetProvisioningState()
		if err != nil {
			log.Error("Failed to get provisioning state: ", err)
		} else {
			result.ProvisioningState = utils.InterpretProvisioningState(provState)
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

	// Ensure WSMAN client is set up once for any operations that need it (RAS, UserCert)
	if showAll || cmd.Ras || cmd.UserCert {
		if controlMode == -1 {
			controlMode, controlModeErr = s.amtCommand.GetControlMode()
		}

		if controlModeErr == nil {
			if err := s.ensureWSMANClient(controlMode); err != nil {
				log.Debug("WSMAN client setup failed, WSMAN features unavailable: ", err)
			}
		}
	}

	// Get RAS (Remote Access Status)
	if showAll || cmd.Ras {
		// Try WSMAN first for MPS hostname + port
		var (
			wsmanHostname string
			wsmanPort     int
			wsmanErr      error
		)

		wsmanHostname, wsmanPort, wsmanErr = s.getMPSInfoFromWSMAN()
		if wsmanErr != nil {
			log.Debug("Failed to get MPS info from WSMAN, will use HECI: ", wsmanErr)
		}

		// Always call HECI for NetworkStatus, RemoteStatus, RemoteTrigger
		ras, err := s.amtCommand.GetRemoteAccessConnectionStatus()
		if err == nil {
			if wsmanErr == nil {
				// WSMAN succeeded: use WSMAN hostname + port
				ras.MPSHostname = wsmanHostname
				ras.MPSPort = wsmanPort
			}
			// If WSMAN failed, HECI hostname is already in ras.MPSHostname; port stays 0
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
	if cmd.Cert || cmd.All {
		certResult, err := s.amtCommand.GetCertificateHashes()
		if err == nil {
			result.CertificateHashes = make(map[string]amt.CertHashEntry)
			for _, cert := range certResult {
				result.CertificateHashes[cert.Name] = cert
			}
		}
	}

	// Get user certificates (WSMAN client already set up above)
	if cmd.All || cmd.UserCert {
		userCerts, err := s.getUserCertificates()
		if err != nil {
			log.Error("Failed to get user certificates: ", err)
		} else {
			result.UserCerts = userCerts
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
	showAll := cmd.All || cmd.HasNoFlagsSet()

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

	if (showAll || cmd.ProvState) && result.ProvisioningState != "" {
		fmt.Printf("Provisioning State\t: %s\n", result.ProvisioningState)
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

		if result.RAS.MPSPort > 0 {
			fmt.Printf("RAS MPS Port\t\t: %d\n", result.RAS.MPSPort)
		}
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

	// Output UPID information
	if (showAll || cmd.UPID) && result.UPID != nil {
		fmt.Println(result.UPID.String())
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
	if cmd.All || cmd.UserCert {
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

// ensureWSMANClient sets up s.wsman once if not already initialized.
// Uses the AMT password if available, otherwise falls back to LSA credentials.
func (s *InfoService) ensureWSMANClient(controlMode int) error {
	if s.wsman != nil {
		return nil
	}

	if controlMode == 0 {
		return fmt.Errorf("device is in pre-provisioning mode")
	}

	username := "admin"
	password := s.password

	// If no password provided, use local system account credentials
	if password == "" {
		lsa, err := s.amtCommand.GetLocalSystemAccount()
		if err != nil {
			return fmt.Errorf("failed to get local system account: %w", err)
		}

		username = lsa.Username
		password = lsa.Password
	}

	// Check LMS connectivity before attempting WSMAN setup to avoid local transport fallback which hangs.
	port := utils.LMSPort
	if s.localTLSEnforced {
		port = utils.LMSTLSPort
	}

	dialer := &net.Dialer{Timeout: 5 * time.Second}

	conn, err := dialer.DialContext(context.Background(), "tcp4", utils.LMSAddress+":"+port)
	if err != nil {
		return fmt.Errorf("LMS not available: %w", err)
	}

	conn.Close()

	wsmanClient := localamt.NewGoWSMANMessages(utils.LMSAddress)

	var tlsConfig *tls.Config
	if s.localTLSEnforced {
		tlsConfig = certs.GetTLSConfig(&controlMode, nil, s.skipAMTCertCheck)
	} else {
		tlsConfig = &tls.Config{InsecureSkipVerify: s.skipAMTCertCheck}
	}

	if err := wsmanClient.SetupWsmanClient(username, password, s.localTLSEnforced, log.GetLevel() == log.TraceLevel, tlsConfig); err != nil {
		return fmt.Errorf("failed to setup WSMAN client: %w", err)
	}

	s.wsman = wsmanClient

	return nil
}

// getUserCertificates retrieves public key certificates via WSMAN
func (s *InfoService) getUserCertificates() (map[string]UserCert, error) {
	if s.wsman == nil {
		return nil, fmt.Errorf("WSMAN client not available")
	}

	publicKeyCerts, err := s.wsman.GetPublicKeyCerts()
	if err != nil {
		return nil, fmt.Errorf("failed to get public key certificates: %w", err)
	}

	userCertMap := make(map[string]UserCert)

	for _, cert := range publicKeyCerts {
		name := utils.GetTokenFromKeyValuePairs(cert.Subject, "CN")
		if name == "" {
			name = cert.InstanceID
		}

		userCertMap[name] = UserCert{
			Subject:                cert.Subject,
			Issuer:                 cert.Issuer,
			TrustedRootCertificate: cert.TrustedRootCertificate,
			ReadOnlyCertificate:    cert.ReadOnlyCertificate,
		}
	}

	return userCertMap, nil
}

// getMPSInfoFromWSMAN retrieves MPS hostname and port via WSMAN ManagementPresenceRemoteSAP.
func (s *InfoService) getMPSInfoFromWSMAN() (hostname string, port int, err error) {
	if s.wsman == nil {
		return "", 0, fmt.Errorf("WSMAN client not available")
	}

	items, err := s.wsman.GetMPSSAP()
	if err != nil {
		return "", 0, fmt.Errorf("failed to get MPS SAP: %w", err)
	}

	if len(items) == 0 {
		return "", 0, fmt.Errorf("no MPS entries found")
	}

	return items[0].AccessInfo, items[0].Port, nil
}
