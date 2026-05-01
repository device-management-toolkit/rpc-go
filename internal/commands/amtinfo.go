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
	"io"
	"net"
	"net/http"
	neturl "net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/alecthomas/kong"
	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/lipgloss/list"
	"github.com/charmbracelet/lipgloss/table"
	ipshttp "github.com/device-management-toolkit/go-wsman-messages/v2/pkg/wsman/ips/http"
	"github.com/device-management-toolkit/rpc-go/v2/internal/certs"
	"github.com/device-management-toolkit/rpc-go/v2/internal/interfaces"
	localamt "github.com/device-management-toolkit/rpc-go/v2/internal/local/amt"
	"github.com/device-management-toolkit/rpc-go/v2/internal/profile"
	"github.com/device-management-toolkit/rpc-go/v2/pkg/amt"
	"github.com/device-management-toolkit/rpc-go/v2/pkg/upid"
	"github.com/device-management-toolkit/rpc-go/v2/pkg/utils"
	log "github.com/sirupsen/logrus"
	"golang.org/x/term"
)

// Minimum terminal width at which OutputText switches to a two-column layout.
const twoColumnMinWidth = 150

const (
	notFoundIP = "Not Found"
	zeroIP     = "0.0.0.0"
	zeroMAC    = "00:00:00:00:00:00"
)

// Indent constant for consistent text output spacing.
const infoIndent = "  "

// Styling for amtinfo text output.
var (
	infoHeaderStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("39"))

	infoSepStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("236"))

	infoLabelStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("250")).
			Width(30)

	infoGreenStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("78"))

	infoYellowStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("220"))

	infoRedStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("168"))

	infoDimStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("243"))

	infoCertNameStyle = lipgloss.NewStyle().
				Bold(true)

	boxBorderColor = lipgloss.Color("238")

	boxBorderStyle = lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(boxBorderColor).
			Padding(1, 1)

	boxBorderCharStyle = lipgloss.NewStyle().
				Foreground(boxBorderColor)

	boxTitleStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("39"))
)

func renderInfoHeader(title string) string {
	return "\n" + infoIndent + infoHeaderStyle.Render(title) + "\n" + infoIndent +
		infoSepStyle.Render(strings.Repeat("─", len([]rune(title)))) + "\n"
}

func renderInfoRow(label, value string) string {
	return infoIndent + infoLabelStyle.Render(label) + " " + styledInfoValue(value) + "\n"
}

func styledInfoValue(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "enabled", "connected", "up", "active",
		"post-provisioning", "admin control mode":
		return infoGreenStyle.Render(value)
	case "disabled", "not connected", "down",
		"not activated", "unknown":
		return infoRedStyle.Render(value)
	case "in provisioning",
		"client control mode":
		return infoYellowStyle.Render(value)
	default:
		return value
	}
}

// renderTitledBox wraps content in a rounded bordered box with a title
// embedded in the top border, like: ╭─ Title ───────╮.
// If width > 0, the box content is padded to that width.
// If height > 0, content is vertically centered within that height.
func renderTitledBox(title, content string, width, height int) string {
	style := boxBorderStyle
	if width > 0 {
		style = style.Width(width)
	}

	if height > 0 {
		style = style.Height(height).AlignVertical(lipgloss.Center)
	}

	box := style.Render(content)

	lines := strings.Split(box, "\n")
	if len(lines) < 3 {
		return box
	}

	// Compute visual (printable) width of the original top border.
	topWidth := lipgloss.Width(lines[0])

	styledTitle := boxTitleStyle.Render(" " + title + " ")
	titleWidth := lipgloss.Width(styledTitle)

	// Need room for: left corner (1) + one leading dash (1) + title + right corner (1).
	if 3+titleWidth > topWidth {
		return box
	}

	remaining := topWidth - 3 - titleWidth
	lines[0] = boxBorderCharStyle.Render("╭─") + styledTitle +
		boxBorderCharStyle.Render(strings.Repeat("─", remaining)+"╮")

	return strings.Join(lines, "\n")
}

func indentBlock(s, prefix string) string {
	lines := strings.Split(s, "\n")
	for i, line := range lines {
		if line != "" {
			lines[i] = prefix + line
		}
	}

	return strings.Join(lines, "\n")
}

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
	UserCert bool `help:"Show User Certificates only" name:"userCert"`

	// Proxy flags
	Proxy bool `help:"Show HTTP Proxy Configuration (requires WSMAN)" name:"proxy"`

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

// BeforeApply is called by Kong before AfterApply. Setting SkipWSMANSetup here
// ensures AMTBaseCmd.AfterApply can tolerate HECI failures for amtinfo.
func (cmd *AmtInfoCmd) BeforeApply() error {
	cmd.SkipWSMANSetup = true

	return nil
}

// Validate implements Kong's extensible validation interface for business logic validation
func (cmd *AmtInfoCmd) Validate(kctx *kong.Context) error {
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
		!cmd.Cert && !cmd.UserCert && !cmd.Ras && !cmd.Lan && !cmd.Hostname && !cmd.OpState && !cmd.Proxy
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
	service.heciAvailable = cmd.HECIAvailable

	if cmd.Sync && !cmd.HECIAvailable {
		return fmt.Errorf("--sync requires administrator privileges and MEI driver to gather device data")
	}

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
		return service.OutputJSON(os.Stdout, result)
	}

	if ctx.TableOutput {
		if err := service.OutputTable(os.Stdout, result, cmd); err != nil {
			return err
		}
	} else {
		if err := service.OutputText(os.Stdout, result, cmd); err != nil {
			return err
		}
	}

	// Signal to Execute() that elevation would unlock more data
	if !cmd.HECIAvailable && !utils.IsElevated() {
		return utils.IncorrectPermissions
	}

	return nil
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
	ProxyAccessPoints *[]ProxyAccessPoint          `json:"proxyAccessPoints,omitempty"`
	HECIAvailable     *bool                        `json:"heciAvailable,omitempty"`
}

// UserCert represents a user certificate
type UserCert struct {
	Subject                string `json:"subject,omitempty"`
	Issuer                 string `json:"issuer,omitempty"`
	TrustedRootCertificate bool   `json:"trustedRootCertificate,omitempty"`
	ReadOnlyCertificate    bool   `json:"readOnlyCertificate,omitempty"`
}

// ProxyAccessPoint represents an HTTP proxy access point configured in AMT.
type ProxyAccessPoint struct {
	Address          string `json:"address"`
	Port             int    `json:"port"`
	NetworkDnsSuffix string `json:"networkDnsSuffix"`
	InfoFormat       string `json:"infoFormat"`
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
	heciAvailable    bool
}

// NewInfoService creates a new InfoService with the given AMT command.
// heciAvailable defaults to true for backward compatibility with existing callers.
func NewInfoService(amtCommand amt.Interface) *InfoService {
	return &InfoService{
		amtCommand:       amtCommand,
		jsonOutput:       false,
		password:         "",
		localTLSEnforced: false,
		skipAMTCertCheck: false,
		wsman:            nil,
		heciAvailable:    true,
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

	// Surface HECI availability in JSON output
	heciFlag := s.heciAvailable
	result.HECIAvailable = &heciFlag

	// Get AMT version information (requires HECI)
	if showAll || cmd.Ver {
		if s.heciAvailable {
			version, err := s.amtCommand.GetVersionDataFromME("AMT", 2*time.Minute)
			if err != nil {
				log.Error("Failed to get AMT version: ", err)
			} else {
				result.AMT = version
			}
		}
	}

	// Get build number (requires HECI)
	if showAll || cmd.Bld {
		if s.heciAvailable {
			build, err := s.amtCommand.GetVersionDataFromME("Build Number", 2*time.Minute)
			if err != nil {
				log.Error("Failed to get build number: ", err)
			} else {
				result.BuildNumber = build
			}
		}
	}

	// Get SKU (requires HECI)
	if showAll || cmd.Sku {
		if s.heciAvailable {
			sku, err := s.amtCommand.GetVersionDataFromME("Sku", 2*time.Minute)
			if err != nil {
				log.Error("Failed to get SKU: ", err)
			} else {
				result.SKU = sku
			}
		}
	}

	// Decode AMT features if we have both version and SKU and both flags are set
	if (showAll || (cmd.Ver && cmd.Sku)) && result.AMT != "" && result.SKU != "" {
		result.Features = strings.TrimSpace(utils.DecodeAMTFeatures(result.AMT, result.SKU))
	}

	// Get UUID (requires HECI)
	if showAll || cmd.UUID {
		if s.heciAvailable {
			uuid, err := s.amtCommand.GetUUID()
			if err != nil {
				log.Error("Failed to get UUID: ", err)
			} else {
				result.UUID = uuid
			}
		}
	}

	// Get UPID (Intel Unique Platform ID) — uses its own HECI client, handles errors internally
	if showAll || cmd.UPID {
		upidData, err := s.amtCommand.GetUPID()
		if err != nil {
			log.Trace("Failed to get UPID: ", err)
		} else if upidData != nil {
			result.UPID = upidData
		}
	}

	// Get control mode (requires HECI)
	if showAll || cmd.Mode {
		if s.heciAvailable {
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
	}

	// Get provisioning state (requires HECI)
	if showAll || cmd.ProvState {
		if s.heciAvailable {
			provState, err := s.amtCommand.GetProvisioningState()
			if err != nil {
				log.Error("Failed to get provisioning state: ", err)
			} else {
				result.ProvisioningState = utils.InterpretProvisioningState(provState)
			}
		}
	}

	// Get operational state (requires HECI, for AMT versions > 11)
	if showAll || cmd.OpState {
		if s.heciAvailable {
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
	}

	// Get DNS information
	if showAll || cmd.DNS {
		// AMT DNS suffix (requires HECI)
		if s.heciAvailable {
			dnsSuffix, err := s.amtCommand.GetDNSSuffix()
			if err == nil {
				result.DNSSuffix = dnsSuffix
			}
		}

		// OS DNS suffix (no admin required)
		osDnsSuffix, err := s.amtCommand.GetOSDNSSuffix()
		if err == nil {
			result.DNSSuffixOS = osDnsSuffix
		}
	}

	// Get hostname from OS (no admin required)
	if showAll || cmd.Hostname {
		hostname, err := os.Hostname()
		if err == nil {
			result.HostnameOS = hostname
		}
	}

	// Ensure WSMAN client is set up once for any operations that need it (RAS, UserCert, Proxy)
	if s.heciAvailable && (showAll || cmd.Ras || cmd.UserCert || cmd.Proxy) {
		if controlMode == -1 {
			controlMode, controlModeErr = s.amtCommand.GetControlMode()
		}

		if controlModeErr == nil {
			if err := s.ensureWSMANClient(controlMode); err != nil {
				log.Debug("WSMAN client setup failed, WSMAN features unavailable: ", err)
			}
		}
	}

	// Get RAS (Remote Access Status) (requires HECI)
	if showAll || cmd.Ras {
		if s.heciAvailable {
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
	}

	// Get LAN interface settings (requires HECI)
	if showAll || cmd.Lan {
		if s.heciAvailable {
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
	}

	// Get certificate hashes (requires HECI)
	if cmd.Cert || cmd.All {
		if s.heciAvailable {
			certResult, err := s.amtCommand.GetCertificateHashes()
			if err == nil {
				result.CertificateHashes = make(map[string]amt.CertHashEntry)
				for _, cert := range certResult {
					result.CertificateHashes[cert.Name] = cert
				}
			}
		}
	}

	// Get user certificates (requires WSMAN/HECI)
	if cmd.All || cmd.UserCert {
		if s.heciAvailable {
			userCerts, err := s.getUserCertificates()
			if err != nil {
				log.Error("Failed to get user certificates: ", err)
			} else {
				result.UserCerts = userCerts
			}
		}
	}

	// Get HTTP proxy access points (requires WSMAN/HECI)
	if showAll || cmd.Proxy {
		if s.heciAvailable {
			proxies, err := s.getProxyAccessPoints()
			if err != nil {
				log.Debug("Failed to get HTTP proxy access points: ", err)
			} else {
				result.ProxyAccessPoints = &proxies
			}
		}
	}

	return result, nil
}

// OutputJSON outputs the result in JSON format
func (s *InfoService) OutputJSON(w io.Writer, result *InfoResult) error {
	jsonBytes, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal JSON: %w", err)
	}

	fmt.Fprintln(w, string(jsonBytes))

	return nil
}

// Table styling
var (
	tableHeaderStyle = lipgloss.NewStyle().
				Bold(true).
				Foreground(lipgloss.Color("39")).
				Align(lipgloss.Center)

	tableCellStyle = lipgloss.NewStyle().
			PaddingLeft(1).
			PaddingRight(1)

	tableBorderStyle = lipgloss.NewStyle().
				Foreground(lipgloss.Color("238"))
)

// OutputTable outputs the result as a single styled table with Category, Flag, Property, and Value columns
func (s *InfoService) OutputTable(w io.Writer, result *InfoResult, cmd *AmtInfoCmd) error {
	showAll := cmd.All || cmd.HasNoFlagsSet()

	if !s.heciAvailable {
		fmt.Fprintln(w)

		if !utils.IsElevated() {
			fmt.Fprintln(w, infoIndent+infoYellowStyle.Render(
				"Not running as administrator \u2014 AMT data unavailable"))
			fmt.Fprintln(w, infoIndent+infoDimStyle.Render(
				"Showing OS-level information only"))
		} else {
			fmt.Fprintln(w, infoIndent+infoYellowStyle.Render(
				"MEI/HECI driver not detected \u2014 AMT may not be available on this device"))
		}
	}

	type row struct {
		category, flag, property, value string
	}

	var rows []row

	add := func(cat, flag, prop, val string) {
		rows = append(rows, row{cat, flag, prop, val})
	}

	// --- Device ---
	if (showAll || cmd.Ver) && result.AMT != "" {
		add("Device", "-r", "Version", result.AMT)
	}

	if (showAll || cmd.Bld) && result.BuildNumber != "" {
		add("Device", "-b", "Build Number", result.BuildNumber)
	}

	if (showAll || cmd.Sku) && result.SKU != "" {
		add("Device", "-s", "SKU", result.SKU)
	}

	if (showAll || (cmd.Ver && cmd.Sku)) && result.Features != "" {
		add("Device", "-r -s", "Features", result.Features)
	}

	if (showAll || cmd.UUID) && result.UUID != "" {
		add("Device", "-u", "UUID", result.UUID)
	}

	if (showAll || cmd.Mode) && result.ControlMode != "" {
		add("Device", "-m", "Control Mode", result.ControlMode)
	}

	if (showAll || cmd.ProvState) && result.ProvisioningState != "" {
		add("Device", "-p", "Provisioning State", result.ProvisioningState)
	}

	if (showAll || cmd.OpState) && result.OperationalState != "" {
		add("Device", "--operationalState", "AMT Operational State (BIOS)", result.OperationalState)
	}

	if showAll || cmd.DNS {
		add("Device", "-d", "DNS Suffix", result.DNSSuffix)
		add("Device", "-d", "DNS Suffix (OS)", result.DNSSuffixOS)
	}

	if (showAll || cmd.Hostname) && result.HostnameOS != "" {
		add("Device", "--hostname", "Hostname (OS)", result.HostnameOS)
	}

	// --- Remote Access ---
	if (showAll || cmd.Ras) && result.RAS != nil {
		add("Remote Access", "-a", "Network", result.RAS.NetworkStatus)
		add("Remote Access", "-a", "Remote Status", result.RAS.RemoteStatus)
		add("Remote Access", "-a", "Trigger", result.RAS.RemoteTrigger)
		add("Remote Access", "-a", "MPS Hostname", result.RAS.MPSHostname)

		if result.RAS.MPSPort > 0 {
			add("Remote Access", "-a", "MPS Port", strconv.Itoa(result.RAS.MPSPort))
		}
	}

	// --- Wired Adapter ---
	if (showAll || cmd.Lan) && result.WiredAdapter != nil && result.WiredAdapter.MACAddress != zeroMAC {
		add("Wired Adapter", "-l", "DHCP Enabled", strconv.FormatBool(result.WiredAdapter.DHCPEnabled))
		add("Wired Adapter", "-l", "DHCP Mode", result.WiredAdapter.DHCPMode)
		add("Wired Adapter", "-l", "Link Status", result.WiredAdapter.LinkStatus)
		add("Wired Adapter", "-l", "AMT IP Address", result.WiredAdapter.IPAddress)
		add("Wired Adapter", "-l", "OS IP Address", result.WiredAdapter.OsIPAddress)
		add("Wired Adapter", "-l", "MAC Address", result.WiredAdapter.MACAddress)
	}

	// --- Wireless Adapter ---
	if (showAll || cmd.Lan) && result.WirelessAdapter != nil {
		add("Wireless Adapter", "-l", "DHCP Enabled", strconv.FormatBool(result.WirelessAdapter.DHCPEnabled))
		add("Wireless Adapter", "-l", "DHCP Mode", result.WirelessAdapter.DHCPMode)
		add("Wireless Adapter", "-l", "Link Status", result.WirelessAdapter.LinkStatus)
		add("Wireless Adapter", "-l", "AMT IP Address", result.WirelessAdapter.IPAddress)
		add("Wireless Adapter", "-l", "OS IP Address", result.WirelessAdapter.OsIPAddress)
		add("Wireless Adapter", "-l", "MAC Address", result.WirelessAdapter.MACAddress)
	}

	// --- Intel UPID ---
	if (showAll || cmd.UPID) && result.UPID != nil {
		upidStr := result.UPID.String()
		for _, line := range strings.Split(upidStr, "\n") {
			if strings.HasPrefix(line, "---") {
				continue
			}

			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				label := strings.TrimSpace(parts[0])
				value := strings.TrimSpace(parts[1])

				if label == "OEM_PLATFORM_ID_TYPE" {
					label = "Platform ID Type"
				}

				add("Intel UPID", "--upid", label, value)
			}
		}
	}

	// --- Certificate Hashes ---
	if showAll || cmd.Cert {
		for name, cert := range result.CertificateHashes {
			flags := ""
			if cert.IsDefault {
				flags += "Default "
			}

			if cert.IsActive {
				flags += "Active"
			}

			info := strings.TrimSpace(flags)
			if info != "" {
				info += " | "
			}

			info += cert.Algorithm + ": " + cert.Hash

			add("Certificates", "-c", name, info)
		}
	}

	// --- User Certificates ---
	if cmd.All || cmd.UserCert {
		for name, cert := range result.UserCerts {
			flags := ""
			if cert.TrustedRootCertificate {
				flags += "TrustedRoot "
			}

			if cert.ReadOnlyCertificate {
				flags += "ReadOnly"
			}

			add("User Certs", "--userCert", name, strings.TrimSpace(flags))
		}
	}

	// --- HTTP Proxy ---
	if showAll || cmd.Proxy {
		if result.ProxyAccessPoints != nil && len(*result.ProxyAccessPoints) > 0 {
			for _, ap := range *result.ProxyAccessPoints {
				add("HTTP Proxy", "--proxy", net.JoinHostPort(ap.Address, strconv.Itoa(ap.Port)), ap.InfoFormat+" | "+ap.NetworkDnsSuffix)
			}
		} else if (cmd.Proxy || cmd.All) && result.ProxyAccessPoints != nil {
			add("HTTP Proxy", "--proxy", "None configured", "")
		} else if cmd.Proxy || cmd.All {
			add("HTTP Proxy", "--proxy", "Unavailable", "Proxy configuration could not be retrieved")
		}
	}

	if len(rows) == 0 {
		fmt.Fprintln(w)
		fmt.Fprintln(w, infoDimStyle.Render(infoIndent+"No matching information found."))
		fmt.Fprintln(w)

		return nil
	}

	// Collapse duplicate category and flag labels within each group,
	// and insert empty separator rows between categories.
	var tableRows [][]string

	separatorRows := map[int]bool{}
	prevCat := ""
	prevFlag := ""

	for _, r := range rows {
		cat := r.category
		flag := r.flag

		if cat == prevCat {
			if flag == prevFlag {
				flag = ""
			} else {
				prevFlag = flag
			}

			cat = ""
		} else {
			// Insert a blank separator row before each new category (except the first)
			if prevCat != "" {
				separatorRows[len(tableRows)] = true
				tableRows = append(tableRows, []string{"", "", "", ""})
			}

			prevCat = cat
			prevFlag = flag
		}

		tableRows = append(tableRows, []string{cat, flag, r.property, r.value})
	}

	flagStyle := lipgloss.NewStyle().
		PaddingLeft(1).
		PaddingRight(1).
		Foreground(lipgloss.Color("243"))

	separatorStyle := lipgloss.NewStyle().
		Foreground(lipgloss.Color("238")).
		Height(0)

	t := table.New().
		Headers("Category", "Flag", "Property", "Value").
		Rows(tableRows...).
		BorderStyle(tableBorderStyle).
		StyleFunc(func(row, col int) lipgloss.Style {
			if row == table.HeaderRow {
				return tableHeaderStyle
			}

			if separatorRows[row] {
				return separatorStyle
			}

			switch col {
			case 0:
				return tableCellStyle.Foreground(lipgloss.Color("39")).Bold(true)
			case 1:
				return flagStyle
			default:
				return tableCellStyle
			}
		})

	fmt.Fprintln(w)
	fmt.Fprintln(w, t.Render())
	fmt.Fprintln(w)

	return nil
}

// OutputText outputs the result in styled human-readable text format
func (s *InfoService) OutputText(w io.Writer, result *InfoResult, cmd *AmtInfoCmd) error {
	showAll := cmd.All || cmd.HasNoFlagsSet()

	var b strings.Builder

	if !s.heciAvailable {
		if !utils.IsElevated() {
			b.WriteString("\n" + infoIndent + infoYellowStyle.Render(
				"Not running as administrator \u2014 AMT data unavailable") + "\n")
			b.WriteString(infoIndent + infoDimStyle.Render(
				"Showing OS-level information only") + "\n")
		} else {
			b.WriteString("\n" + infoIndent + infoYellowStyle.Render(
				"MEI/HECI driver not detected \u2014 AMT may not be available on this device") + "\n")
		}
	}

	// Build unboxed sections first; they're the default output.
	deviceSec := buildDeviceSection(result, cmd, showAll, false)
	rasSec := buildRASSection(result, cmd, showAll)
	proxySec := buildProxySection(result, cmd, showAll, s.heciAvailable)
	wiredSec := buildWiredSection(result, cmd, showAll, false)
	wirelessSec := buildWirelessSection(result, cmd, showAll, false)
	upidSec := buildUPIDSection(result, cmd, showAll)
	userCertsSec := buildUserCertsSection(result, cmd)

	// Only use boxed two-column layout when the terminal is wide enough AND
	// both sides have content to display. Otherwise fall through to single-column.
	leftHasContent := deviceSec != "" || upidSec != "" || rasSec != "" || proxySec != ""
	rightHasContent := wiredSec != "" || wirelessSec != ""

	termW := getTerminalWidth()

	if termW >= twoColumnMinWidth && leftHasContent && rightHasContent {
		// Rebuild sections whose header differs inside a box.
		deviceBoxed := buildDeviceSection(result, cmd, showAll, true)
		wiredBoxed := buildWiredSection(result, cmd, showAll, true)
		wirelessBoxed := buildWirelessSection(result, cmd, showAll, true)

		left := strings.Trim(deviceBoxed+upidSec+rasSec+proxySec, "\n")
		right := strings.Trim(wiredBoxed+wirelessBoxed, "\n")

		// Baseline colWidth from upper content (+2 for Padding(1, 1) horizontal).
		upperContentW := maxInt(lipgloss.Width(left), lipgloss.Width(right))
		baseColWidth := upperContentW + 2

		// Attempt 2-col cert hashes. If the resulting cert box outer width
		// (2*colWidth + 6) would overflow the terminal, fall back to 1-col.
		certsTwoCol := buildCertsSection(result, cmd, showAll, true)
		certsOneCol := buildCertsSection(result, cmd, showAll, false)

		tryCertContent := strings.Trim(userCertsSec+certsTwoCol, "\n")
		certNaturalW := lipgloss.Width(tryCertContent)

		// colWidth derived so that cert box inner (colWidth*2 + 4) holds the
		// natural 2-col content + Padding(1, 1) horizontal (+2).
		// Solving: 2*colWidth + 4 >= certNaturalW + 2
		//          colWidth >= (certNaturalW - 2) / 2
		colFromCerts := (certNaturalW - 2 + 1) / 2

		colWidth := maxInt(baseColWidth, colFromCerts)

		var certContent string
		// Outer width of combined upper boxes + gutter: 2*(colWidth+2) + 2.
		if 2*(colWidth+2)+2 <= termW {
			certContent = tryCertContent
		} else {
			// Two-column hashes would overflow — fall back to one column
			// and shrink colWidth to just what upper content needs.
			colWidth = baseColWidth
			certContent = strings.Trim(userCertsSec+certsOneCol, "\n")
		}

		colHeight := maxInt(lipgloss.Height(left), lipgloss.Height(right)) + 2

		leftBox := renderTitledBox("Device Information", left, colWidth, colHeight)
		rightBox := renderTitledBox("Network Adapters", right, colWidth, colHeight)

		b.WriteString("\n")
		b.WriteString(lipgloss.JoinHorizontal(lipgloss.Top, leftBox, "  ", rightBox))
		b.WriteString("\n")

		if certContent != "" {
			certBox := renderTitledBox("Certificates", certContent, colWidth*2+4, 0)
			b.WriteString(certBox)
			b.WriteString("\n")
		}
	} else {
		b.WriteString(deviceSec)
		b.WriteString(rasSec)
		b.WriteString(proxySec)
		b.WriteString(wiredSec)
		b.WriteString(wirelessSec)
		b.WriteString(upidSec)
		b.WriteString(userCertsSec)
		b.WriteString(buildCertsSection(result, cmd, showAll, false))
	}

	if b.Len() > 0 {
		b.WriteString("\n")
	}

	if _, err := fmt.Fprint(w, b.String()); err != nil {
		return err
	}

	return nil
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}

	return b
}

// getTerminalWidth returns the width of the controlling terminal in columns,
// or 0 if stdout is not a terminal (piped, redirected, or in tests).
// It is a var so tests can override it to exercise the two-column layout.
var getTerminalWidth = func() int {
	w, _, err := term.GetSize(int(os.Stdout.Fd()))
	if err != nil {
		return 0
	}

	return w
}

// buildDeviceSection renders the device info block. When boxed is true, the
// sub-header is omitted because the enclosing box's title serves the same role.
func buildDeviceSection(result *InfoResult, cmd *AmtInfoCmd, showAll, boxed bool) string {
	var main strings.Builder

	if (showAll || cmd.Ver) && result.AMT != "" {
		main.WriteString(renderInfoRow("Version", result.AMT))
	}

	if (showAll || cmd.Bld) && result.BuildNumber != "" {
		main.WriteString(renderInfoRow("Build Number", result.BuildNumber))
	}

	if (showAll || cmd.Sku) && result.SKU != "" {
		main.WriteString(renderInfoRow("SKU", result.SKU))
	}

	if (showAll || (cmd.Ver && cmd.Sku)) && result.Features != "" {
		main.WriteString(renderInfoRow("Features", result.Features))
	}

	if (showAll || cmd.UUID) && result.UUID != "" {
		main.WriteString(renderInfoRow("UUID", result.UUID))
	}

	if (showAll || cmd.Mode) && result.ControlMode != "" {
		main.WriteString(renderInfoRow("Control Mode", result.ControlMode))
	}

	if (showAll || cmd.ProvState) && result.ProvisioningState != "" {
		main.WriteString(renderInfoRow("Provisioning State", result.ProvisioningState))
	}

	if (showAll || cmd.OpState) && result.OperationalState != "" {
		main.WriteString(renderInfoRow("AMT Operational State (BIOS)", result.OperationalState))
	}

	if showAll || cmd.DNS {
		main.WriteString(renderInfoRow("DNS Suffix", result.DNSSuffix))
		main.WriteString(renderInfoRow("DNS Suffix (OS)", result.DNSSuffixOS))
	}

	if (showAll || cmd.Hostname) && result.HostnameOS != "" {
		main.WriteString(renderInfoRow("Hostname (OS)", result.HostnameOS))
	}

	if main.Len() == 0 {
		return ""
	}

	if boxed {
		return main.String()
	}

	return renderInfoHeader("AMT Device Information") + main.String()
}

func buildRASSection(result *InfoResult, cmd *AmtInfoCmd, showAll bool) string {
	if (!showAll && !cmd.Ras) || result.RAS == nil {
		return ""
	}

	var b strings.Builder

	b.WriteString(renderInfoHeader("Remote Access"))
	b.WriteString(renderInfoRow("Network", result.RAS.NetworkStatus))
	b.WriteString(renderInfoRow("Remote Status", result.RAS.RemoteStatus))
	b.WriteString(renderInfoRow("Trigger", result.RAS.RemoteTrigger))
	b.WriteString(renderInfoRow("MPS Hostname", result.RAS.MPSHostname))

	if result.RAS.MPSPort > 0 {
		b.WriteString(renderInfoRow("MPS Port", strconv.Itoa(result.RAS.MPSPort)))
	}

	return b.String()
}

// buildWiredSection renders the wired adapter block. When boxed is true, the
// header drops "Adapter" since the enclosing "Network Adapters" box provides that context.
func buildWiredSection(result *InfoResult, cmd *AmtInfoCmd, showAll, boxed bool) string {
	if (!showAll && !cmd.Lan) || result.WiredAdapter == nil || result.WiredAdapter.MACAddress == zeroMAC {
		return ""
	}

	header := "Wired Adapter"
	if boxed {
		header = "Wired"
	}

	var b strings.Builder

	b.WriteString(renderInfoHeader(header))
	b.WriteString(renderInfoRow("DHCP Enabled", strconv.FormatBool(result.WiredAdapter.DHCPEnabled)))
	b.WriteString(renderInfoRow("DHCP Mode", result.WiredAdapter.DHCPMode))
	b.WriteString(renderInfoRow("Link Status", result.WiredAdapter.LinkStatus))
	b.WriteString(renderInfoRow("AMT IP Address", result.WiredAdapter.IPAddress))
	b.WriteString(renderInfoRow("OS IP Address", result.WiredAdapter.OsIPAddress))
	b.WriteString(renderInfoRow("MAC Address", result.WiredAdapter.MACAddress))

	return b.String()
}

// buildWirelessSection renders the wireless adapter block. When boxed is true, the
// header drops "Adapter" since the enclosing "Network Adapters" box provides that context.
func buildWirelessSection(result *InfoResult, cmd *AmtInfoCmd, showAll, boxed bool) string {
	if (!showAll && !cmd.Lan) || result.WirelessAdapter == nil {
		return ""
	}

	header := "Wireless Adapter"
	if boxed {
		header = "Wireless"
	}

	var b strings.Builder

	b.WriteString(renderInfoHeader(header))
	b.WriteString(renderInfoRow("DHCP Enabled", strconv.FormatBool(result.WirelessAdapter.DHCPEnabled)))
	b.WriteString(renderInfoRow("DHCP Mode", result.WirelessAdapter.DHCPMode))
	b.WriteString(renderInfoRow("Link Status", result.WirelessAdapter.LinkStatus))
	b.WriteString(renderInfoRow("AMT IP Address", result.WirelessAdapter.IPAddress))
	b.WriteString(renderInfoRow("OS IP Address", result.WirelessAdapter.OsIPAddress))
	b.WriteString(renderInfoRow("MAC Address", result.WirelessAdapter.MACAddress))

	return b.String()
}

func buildProxySection(result *InfoResult, cmd *AmtInfoCmd, showAll, heciAvailable bool) string {
	if !showAll && !cmd.Proxy {
		return ""
	}

	if result.ProxyAccessPoints != nil && len(*result.ProxyAccessPoints) > 0 {
		var b strings.Builder

		b.WriteString(renderInfoHeader("HTTP Proxy Configuration"))

		for _, ap := range *result.ProxyAccessPoints {
			b.WriteString(renderInfoRow("Address", ap.Address))
			b.WriteString(renderInfoRow("Port", strconv.Itoa(ap.Port)))
			b.WriteString(renderInfoRow("Type", ap.InfoFormat))
			b.WriteString(renderInfoRow("Network DNS Suffix", ap.NetworkDnsSuffix))
			b.WriteString("\n")
		}

		return b.String()
	}

	// Empty/missing proxy info is only surfaced when the user explicitly asked
	// for it (--proxy or -A). The default "show all" view hides it.
	if !cmd.Proxy && !cmd.All {
		return ""
	}

	if result.ProxyAccessPoints != nil {
		return renderInfoHeader("HTTP Proxy Configuration") +
			infoIndent + infoDimStyle.Render("No HTTP proxy access points configured") + "\n"
	}

	// Without HECI/admin, WSMAN can't run and "could not be retrieved" is just
	// noise — the top-of-output banner already explains the situation.
	if !heciAvailable {
		return ""
	}

	return renderInfoHeader("HTTP Proxy Configuration") +
		infoIndent + infoRedStyle.Render("Proxy configuration could not be retrieved") + "\n"
}

func buildUPIDSection(result *InfoResult, cmd *AmtInfoCmd, showAll bool) string {
	if (!showAll && !cmd.UPID) || result.UPID == nil {
		return ""
	}

	var b strings.Builder

	b.WriteString(renderInfoHeader("Intel UPID"))

	for _, line := range strings.Split(result.UPID.String(), "\n") {
		if strings.HasPrefix(line, "---") {
			continue
		}

		parts := strings.SplitN(line, ":", 2)
		if len(parts) == 2 {
			label := strings.TrimSpace(parts[0])
			value := strings.TrimSpace(parts[1])

			if label == "OEM_PLATFORM_ID_TYPE" {
				label = "Platform ID Type"
			}

			b.WriteString(renderInfoRow(label, value))
		}
	}

	return b.String()
}

// buildCertsSection renders the Certificate Hashes block.
// When twoCol is true and there are more than a handful of certs, the list
// is split into two side-by-side halves to reduce vertical space.
func buildCertsSection(result *InfoResult, cmd *AmtInfoCmd, showAll, twoCol bool) string {
	if !showAll && !cmd.Cert {
		return ""
	}

	if len(result.CertificateHashes) == 0 {
		if cmd.Cert {
			return renderInfoHeader("Certificate Hashes") +
				infoIndent + infoDimStyle.Render("No certificate hashes found") + "\n"
		}

		return ""
	}

	names := make([]string, 0, len(result.CertificateHashes))
	for name := range result.CertificateHashes {
		names = append(names, name)
	}

	sort.Strings(names)

	renderHalf := func(subset []string) string {
		l := list.New().
			EnumeratorStyle(infoDimStyle).
			ItemStyleFunc(func(_ list.Items, _ int) lipgloss.Style {
				return lipgloss.NewStyle()
			})

		for _, name := range subset {
			cert := result.CertificateHashes[name]

			var flags []string
			if cert.IsDefault {
				flags = append(flags, "Default")
			}

			if cert.IsActive {
				flags = append(flags, "Active")
			}

			title := infoCertNameStyle.Render(name)
			if len(flags) > 0 {
				title += " " + infoDimStyle.Render("("+strings.Join(flags, ", ")+")")
			}

			sub := list.New(infoDimStyle.Render(cert.Algorithm + ": " + cert.Hash)).
				Enumerator(func(_ list.Items, _ int) string { return "" })

			l.Item(title).Item(sub)
		}

		return l.String()
	}

	var body string

	if twoCol && len(names) > 4 {
		mid := (len(names) + 1) / 2
		leftList := renderHalf(names[:mid])
		rightList := lipgloss.NewStyle().MarginLeft(4).Render(renderHalf(names[mid:]))
		body = lipgloss.JoinHorizontal(lipgloss.Top, leftList, rightList)
	} else {
		body = renderHalf(names)
	}

	return renderInfoHeader("Certificate Hashes") + indentBlock(body, infoIndent) + "\n"
}

func buildUserCertsSection(result *InfoResult, cmd *AmtInfoCmd) string {
	if !cmd.All && !cmd.UserCert {
		return ""
	}

	if len(result.UserCerts) == 0 {
		if cmd.UserCert {
			return renderInfoHeader("Public Key Certificates") +
				infoIndent + infoDimStyle.Render("No public key certificates found") + "\n"
		}

		return ""
	}

	names := make([]string, 0, len(result.UserCerts))
	for name := range result.UserCerts {
		names = append(names, name)
	}

	sort.Strings(names)

	l := list.New().
		EnumeratorStyle(infoDimStyle).
		ItemStyleFunc(func(_ list.Items, _ int) lipgloss.Style {
			return lipgloss.NewStyle()
		})

	for _, name := range names {
		cert := result.UserCerts[name]

		var flags []string
		if cert.TrustedRootCertificate {
			flags = append(flags, "TrustedRoot")
		}

		if cert.ReadOnlyCertificate {
			flags = append(flags, "ReadOnly")
		}

		title := infoCertNameStyle.Render(name)
		if len(flags) > 0 {
			title += " " + infoDimStyle.Render("("+strings.Join(flags, ", ")+")")
		}

		l.Item(title)
	}

	return renderInfoHeader("Public Key Certificates") + indentBlock(l.String(), infoIndent) + "\n"
}

// getOSIPAddress gets the OS IP address for a given MAC address
func (s *InfoService) getOSIPAddress(macAddr string) string {
	if macAddr == zeroMAC {
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

	// SetupWsmanClient falls back to HECI/LME when LMS is absent; no need to gate on LMS here.
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

// getProxyAccessPoints retrieves HTTP proxy access points via WSMAN.
func (s *InfoService) getProxyAccessPoints() ([]ProxyAccessPoint, error) {
	if s.wsman == nil {
		return nil, fmt.Errorf("WSMAN client not available")
	}

	items, err := s.wsman.GetHTTPProxyAccessPoints()
	if err != nil {
		return nil, fmt.Errorf("failed to get HTTP proxy access points: %w", err)
	}

	proxies := make([]ProxyAccessPoint, 0, len(items))
	for _, ap := range items {
		proxies = append(proxies, ProxyAccessPoint{
			Address:          ap.AccessInfo,
			Port:             ap.Port,
			NetworkDnsSuffix: ap.NetworkDnsSuffix,
			InfoFormat:       proxyInfoFormatString(ap.InfoFormat),
		})
	}

	return proxies, nil
}

func proxyInfoFormatString(format int) string {
	switch ipshttp.InfoFormat(format) {
	case ipshttp.InfoFormatIPv4:
		return "IPv4"
	case ipshttp.InfoFormatIPv6:
		return "IPv6"
	case ipshttp.InfoFormatFQDN:
		return "FQDN"
	default:
		return "Unknown"
	}
}
