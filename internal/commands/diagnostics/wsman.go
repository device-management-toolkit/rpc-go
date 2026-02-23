/*********************************************************************
 * Copyright (c) Intel Corporation 2026
 * SPDX-License-Identifier: Apache-2.0
 *********************************************************************/

package diagnostics

import (
	"context"
	cryptotls "crypto/tls"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/device-management-toolkit/go-wsman-messages/v2/pkg/wsman"
	"github.com/device-management-toolkit/go-wsman-messages/v2/pkg/wsman/client"
	"github.com/device-management-toolkit/rpc-go/v2/internal/certs"
	"github.com/device-management-toolkit/rpc-go/v2/internal/commands"
	localamt "github.com/device-management-toolkit/rpc-go/v2/internal/local/amt"
	"github.com/device-management-toolkit/rpc-go/v2/pkg/utils"
	log "github.com/sirupsen/logrus"
)

// WSManCmd dumps AMT WSMAN diagnostic classes.
type WSManCmd struct {
	List WSManListCmd `cmd:"list" help:"List all supported WSMAN classes (does not fetch data)"`
	Get  WSManGetCmd  `cmd:"get" help:"Retrieve data for one or more WSMAN classes"`
}

// Run executes the WSMAN diagnostics command.
func (cmd *WSManCmd) Run(ctx *commands.Context) error {
	return nil
}

// WSManListCmd lists supported WSMAN classes.
type WSManListCmd struct{}

// Run executes the WSMAN class list command.
func (cmd *WSManListCmd) Run(ctx *commands.Context) error {
	for _, className := range supportedWSMANClassNames() {
		fmt.Println(className)
	}

	return nil
}

// WSManGetCmd retrieves WSMAN class data for diagnostics.
type WSManGetCmd struct {
	DiagnosticsBaseCmd

	Class  []string `help:"Specific WSMAN class to retrieve (repeatable)" name:"class" short:"c"`
	Output string   `help:"Output file path" name:"output" short:"o" default:"stdout"`
	Format string   `help:"Output format" name:"format" short:"f" enum:"json,xml" default:"json"`
	All    bool     `help:"Retrieve data for all available WSMAN classes" name:"all" short:"a"`
}

type classFetcher func(messages wsman.Messages) (any, error)

type classResult struct {
	Class string `json:"class" xml:"class,attr"`
	Data  any    `json:"data" xml:"-"`
	XML   string `json:"-" xml:",cdata"`
}

type unsupportedClassData struct {
	Class   string `json:"class" xml:"Class"`
	Status  string `json:"status" xml:"Status"`
	Message string `json:"message" xml:"Message"`
}

type classFetchErrorData struct {
	Class   string `json:"class" xml:"Class"`
	Status  string `json:"status" xml:"Status"`
	Message string `json:"message" xml:"Message"`
}

type xmlResults struct {
	XMLName xml.Name      `xml:"WSMANClasses"`
	Items   []classResult `xml:"Class"`
}

var wsmanClassFetchers = map[string]classFetcher{
	"AMT_8021XProfile":                    fetchAMT8021XProfile,
	"AMT_AssetTable":                      unsupportedClassFetcher("AMT_AssetTable", "not exposed by current go-wsman-messages API"),
	"AMT_AssetTableService":               unsupportedClassFetcher("AMT_AssetTableService", "not exposed by current go-wsman-messages API"),
	"AMT_AuditLog":                        fetchAMTAuditLog,
	"AMT_BootCapabilities":                fetchAMTBootCapabilities,
	"AMT_BootSettingData":                 fetchAMTBootSettingData,
	"AMT_CryptographicCapabilities":       unsupportedClassFetcher("AMT_CryptographicCapabilities", "not exposed by current go-wsman-messages API"),
	"AMT_EnvironmentDetectionSettingData": fetchAMTEnvironmentDetectionSettingData,
	"AMT_EventLogEntry":                   fetchAMTEventLogEntry,
	"AMT_EthernetPortSettings":            fetchAMTEthernetPortSettings,
	"AMT_GeneralSettings":                 fetchAMTGeneralSettings,
	"AMT_Hdr8021Filter":                   unsupportedClassFetcher("AMT_Hdr8021Filter", "not exposed by current go-wsman-messages API"),
	"AMT_ManagementPresenceRemoteSAP":     fetchAMTManagementPresenceRemoteSAP,
	"AMT_MessageLog":                      fetchAMTMessageLog,
	"AMT_RedirectionService":              fetchAMTRedirectionService,
	"AMT_RemoteAccessCapabilities":        fetchAMTRemoteAccessCapabilities,
	"AMT_RemoteAccessPolicyAppliesToMPS":  fetchAMTRemoteAccessPolicyAppliesToMPS,
	"AMT_RemoteAccessPolicyRule":          fetchAMTRemoteAccessPolicyRule,
	"AMT_SetupAndConfigurationService":    fetchAMTSetupAndConfigurationService,
	"AMT_SystemPowerScheme":               unsupportedClassFetcher("AMT_SystemPowerScheme", "not exposed by current go-wsman-messages API"),
	"AMT_TimeSynchronizationService":      fetchAMTTimeSynchronizationService,
	"AMT_UserInitiatedConnectionService":  fetchAMTUserInitiatedConnectionService,
	"AMT_WiFiPortConfigurationService":    fetchAMTWiFiPortConfigurationService,
	"CIM_BIOSFeature":                     unsupportedClassFetcher("CIM_BIOSFeature", "not exposed by current go-wsman-messages API"),
	"CIM_BIOSElement":                     fetchCIMBIOSElement,
	"CIM_Card":                            fetchCIMCard,
	"CIM_Chassis":                         fetchCIMChassis,
	"CIM_ComputerSystemPackage":           fetchCIMComputerSystemPackage,
	"CIM_EthernetPort":                    unsupportedClassFetcher("CIM_EthernetPort", "not exposed by current go-wsman-messages API"),
	"CIM_KVMRedirectionSAP":               fetchCIMKVMRedirectionSAP,
	"CIM_PowerManagementCapabilities":     unsupportedClassFetcher("CIM_PowerManagementCapabilities", "not exposed by current go-wsman-messages API"),
	"CIM_PowerManagementService":          fetchCIMPowerManagementService,
	"CIM_Processor":                       fetchCIMProcessor,
	"CIM_RedirectionService":              unsupportedClassFetcher("CIM_RedirectionService", "not exposed by current go-wsman-messages API"),
	"CIM_SoftwareIdentity":                fetchCIMSoftwareIdentity,
	"CIM_WiFiEndpoint":                    fetchCIMWiFiEndpoint,
	"CIM_WiFiEndpointCapabilities":        unsupportedClassFetcher("CIM_WiFiEndpointCapabilities", "not exposed by current go-wsman-messages API"),
	"CIM_WiFiEndpointSettings":            fetchCIMWiFiEndpointSettings,
	"CIM_WiFiPort":                        fetchCIMWiFiPort,
	"CIM_WiFiPortCapabilities":            unsupportedClassFetcher("CIM_WiFiPortCapabilities", "not exposed by current go-wsman-messages API"),
	"IPS_HostBasedSetupService":           fetchIPSHostBasedSetupService,
	"IPS_HostBootReason":                  unsupportedClassFetcher("IPS_HostBootReason", "not exposed by current go-wsman-messages API"),
	"IPS_HostIPSettings":                  unsupportedClassFetcher("IPS_HostIPSettings", "not exposed by current go-wsman-messages API"),
	"IPS_HTTPProxyAccessPoint":            fetchIPSHTTPProxyAccessPoint,
	"IPS_IEEE8021xSettings":               fetchIPSIEEE8021xSettings,
	"IPS_IPv6PortSettings":                unsupportedClassFetcher("IPS_IPv6PortSettings", "not exposed by current go-wsman-messages API"),
	"IPS_KVMRedirectionSettingData":       fetchIPSKVMRedirectionSettingData,
	"IPS_LANEndpoint":                     unsupportedClassFetcher("IPS_LANEndpoint", "not exposed by current go-wsman-messages API"),
	"IPS_OptInService":                    fetchIPSOptInService,
	"IPS_ProvisioningRecordLog":           unsupportedClassFetcher("IPS_ProvisioningRecordLog", "not exposed by current go-wsman-messages API"),
	"IPS_ScreenSettingData":               fetchIPSScreenSettingData,
	"IPS_SecIOService":                    fetchIPSSecIOService,
}

// Run executes the WSMAN get command.
func (cmd *WSManGetCmd) Run(ctx *commands.Context) error {
	selectedClasses, err := cmd.resolveClasses()
	if err != nil {
		return err
	}

	if err := cmd.EnsureAMTPassword(ctx, cmd); err != nil {
		return err
	}

	messages, err := cmd.newWSMANMessages(ctx)
	if err != nil {
		return err
	}

	if messages.Client != nil {
		defer func() {
			if closeErr := messages.Client.CloseConnection(); closeErr != nil {
				log.Debugf("failed to close WSMAN client connection: %v", closeErr)
			}
		}()
	}

	results := make([]classResult, 0, len(selectedClasses))
	for _, className := range selectedClasses {
		fetcher := wsmanClassFetchers[className]

		data, fetchErr := fetcher(messages)
		if fetchErr != nil {
			if len(selectedClasses) == 1 {
				return fmt.Errorf("failed to retrieve WSMAN class %s: %w", className, fetchErr)
			}

			log.Warnf("failed to retrieve WSMAN class %s: %v", className, fetchErr)
			results = append(results, classResult{Class: className, Data: classFetchErrorData{
				Class:   className,
				Status:  "fetch_failed",
				Message: fetchErr.Error(),
			}})

			continue
		}

		results = append(results, classResult{Class: className, Data: data})
	}

	rendered, err := renderResults(results, strings.ToLower(strings.TrimSpace(cmd.Format)))
	if err != nil {
		return err
	}

	if strings.EqualFold(strings.TrimSpace(cmd.Output), "stdout") {
		fmt.Println(string(rendered))

		return nil
	}

	outputPath := strings.TrimSpace(cmd.Output)
	outputDir := filepath.Dir(outputPath)
	if outputDir != "." && outputDir != "" {
		if mkErr := os.MkdirAll(outputDir, 0o755); mkErr != nil {
			return fmt.Errorf("failed to create output directory: %w", mkErr)
		}
	}

	if writeErr := os.WriteFile(outputPath, rendered, 0o644); writeErr != nil {
		return fmt.Errorf("failed to write output file: %w", writeErr)
	}

	fmt.Printf("WSMAN class data written to %s\n", outputPath)

	return nil
}

func (cmd *WSManGetCmd) resolveClasses() ([]string, error) {
	if cmd.All && len(cmd.Class) > 0 {
		return nil, fmt.Errorf("--all cannot be used with --class")
	}

	if !cmd.All && len(cmd.Class) == 0 {
		return nil, fmt.Errorf("specify --all or at least one --class")
	}

	if cmd.All {
		return supportedWSMANClassNames(), nil
	}

	seen := map[string]struct{}{}
	selected := make([]string, 0, len(cmd.Class))

	for _, className := range cmd.Class {
		normalized := strings.TrimSpace(className)
		if normalized == "" {
			continue
		}

		if _, ok := wsmanClassFetchers[normalized]; !ok {
			return nil, fmt.Errorf("unsupported WSMAN class: %s", normalized)
		}

		if _, exists := seen[normalized]; exists {
			continue
		}

		seen[normalized] = struct{}{}
		selected = append(selected, normalized)
	}

	if len(selected) == 0 {
		return nil, fmt.Errorf("at least one valid --class must be provided")
	}

	return selected, nil
}

func supportedWSMANClassNames() []string {
	classes := make([]string, 0, len(wsmanClassFetchers))
	for className := range wsmanClassFetchers {
		classes = append(classes, className)
	}

	sort.Strings(classes)

	return classes
}

func renderResults(results []classResult, format string) ([]byte, error) {
	switch format {
	case "json":
		return json.MarshalIndent(results, "", "  ")
	case "xml":
		if len(results) == 1 {
			return xml.MarshalIndent(results[0].Data, "", "  ")
		}

		xmlItems := make([]classResult, 0, len(results))
		for _, result := range results {
			classXML, err := xml.MarshalIndent(result.Data, "", "  ")
			if err != nil {
				return nil, fmt.Errorf("failed to marshal XML data for class %s: %w", result.Class, err)
			}

			xmlItems = append(xmlItems, classResult{
				Class: result.Class,
				XML:   string(classXML),
			})
		}

		return xml.MarshalIndent(xmlResults{Items: xmlItems}, "", "  ")
	default:
		return nil, fmt.Errorf("unsupported format: %s", format)
	}
}

func (cmd *WSManGetCmd) newWSMANMessages(ctx *commands.Context) (wsman.Messages, error) {
	tlsConfig := certs.GetTLSConfig(&cmd.ControlMode, nil, ctx.SkipAMTCertCheck)

	clientParams := client.Parameters{
		Target:         utils.LMSAddress,
		Username:       utils.AMTUserName,
		Password:       ctx.AMTPassword,
		UseDigest:      true,
		UseTLS:         cmd.LocalTLSEnforced,
		TlsConfig:      tlsConfig,
		LogAMTMessages: log.GetLevel() == log.TraceLevel,
	}

	if clientParams.UseTLS {
		clientParams.SelfSignedAllowed = tlsConfig.InsecureSkipVerify

		connectCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		dialer := &cryptotls.Dialer{Config: tlsConfig}
		conn, err := dialer.DialContext(connectCtx, "tcp", utils.LMSAddress+":"+utils.LMSTLSPort)
		if err != nil {
			log.Debugf("failed to connect to LMS TLS endpoint: %v", err)
		} else {
			_ = conn.Close()
		}
	} else {
		connectCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		dialer := &net.Dialer{}
		conn, err := dialer.DialContext(connectCtx, "tcp4", utils.LMSAddress+":"+utils.LMSPort)
		if err != nil {
			clientParams.Transport = localamt.NewLocalTransport()
		} else {
			_ = conn.Close()
		}
	}

	return wsman.NewMessages(clientParams), nil
}

func fetchAMTGeneralSettings(messages wsman.Messages) (any, error) {
	return messages.AMT.GeneralSettings.Get()
}

func fetchAMT8021XProfile(messages wsman.Messages) (any, error) {
	enumerateResponse, err := messages.AMT.IEEE8021xProfile.Enumerate()
	if err != nil {
		return nil, err
	}

	return messages.AMT.IEEE8021xProfile.Pull(enumerateResponse.Body.EnumerateResponse.EnumerationContext)
}

func fetchAMTAuditLog(messages wsman.Messages) (any, error) {
	return messages.AMT.AuditLog.Get()
}

func fetchAMTBootCapabilities(messages wsman.Messages) (any, error) {
	return messages.AMT.BootCapabilities.Get()
}

func fetchAMTBootSettingData(messages wsman.Messages) (any, error) {
	return messages.AMT.BootSettingData.Get()
}

func fetchAMTEnvironmentDetectionSettingData(messages wsman.Messages) (any, error) {
	return messages.AMT.EnvironmentDetectionSettingData.Get()
}

func fetchAMTMessageLog(messages wsman.Messages) (any, error) {
	return messages.AMT.MessageLog.GetRecords(1, 390)
}

func fetchAMTEventLogEntry(messages wsman.Messages) (any, error) {
	return messages.AMT.MessageLog.GetRecords(1, 390)
}

func fetchAMTEthernetPortSettings(messages wsman.Messages) (any, error) {
	enumerateResponse, err := messages.AMT.EthernetPortSettings.Enumerate()
	if err != nil {
		return nil, err
	}

	return messages.AMT.EthernetPortSettings.Pull(enumerateResponse.Body.EnumerateResponse.EnumerationContext)
}

func fetchAMTManagementPresenceRemoteSAP(messages wsman.Messages) (any, error) {
	enumerateResponse, err := messages.AMT.ManagementPresenceRemoteSAP.Enumerate()
	if err != nil {
		return nil, err
	}

	return messages.AMT.ManagementPresenceRemoteSAP.Pull(enumerateResponse.Body.EnumerateResponse.EnumerationContext)
}

func fetchAMTRedirectionService(messages wsman.Messages) (any, error) {
	return messages.AMT.RedirectionService.Get()
}

func fetchAMTRemoteAccessCapabilities(messages wsman.Messages) (any, error) {
	return messages.AMT.RemoteAccessService.Get()
}

func fetchAMTRemoteAccessPolicyRule(messages wsman.Messages) (any, error) {
	enumerateResponse, err := messages.AMT.RemoteAccessPolicyRule.Enumerate()
	if err != nil {
		return nil, err
	}

	return messages.AMT.RemoteAccessPolicyRule.Pull(enumerateResponse.Body.EnumerateResponse.EnumerationContext)
}

func fetchAMTRemoteAccessPolicyAppliesToMPS(messages wsman.Messages) (any, error) {
	enumerateResponse, err := messages.AMT.RemoteAccessPolicyAppliesToMPS.Enumerate()
	if err != nil {
		return nil, err
	}

	return messages.AMT.RemoteAccessPolicyAppliesToMPS.Pull(enumerateResponse.Body.EnumerateResponse.EnumerationContext)
}

func fetchAMTSetupAndConfigurationService(messages wsman.Messages) (any, error) {
	return messages.AMT.SetupAndConfigurationService.Get()
}

func fetchAMTWiFiPortConfigurationService(messages wsman.Messages) (any, error) {
	return messages.AMT.WiFiPortConfigurationService.Get()
}

func fetchAMTUserInitiatedConnectionService(messages wsman.Messages) (any, error) {
	return messages.AMT.UserInitiatedConnectionService.Get()
}

func fetchAMTTimeSynchronizationService(messages wsman.Messages) (any, error) {
	return messages.AMT.TimeSynchronizationService.GetLowAccuracyTimeSynch()
}

func fetchCIMBIOSElement(messages wsman.Messages) (any, error) {
	enumerateResponse, err := messages.CIM.BIOSElement.Enumerate()
	if err != nil {
		return nil, err
	}

	return messages.CIM.BIOSElement.Pull(enumerateResponse.Body.EnumerateResponse.EnumerationContext)
}

func fetchCIMProcessor(messages wsman.Messages) (any, error) {
	return messages.CIM.Processor.Get()
}

func fetchCIMPowerManagementService(messages wsman.Messages) (any, error) {
	return messages.CIM.PowerManagementService.Get()
}

func fetchCIMComputerSystemPackage(messages wsman.Messages) (any, error) {
	return messages.CIM.ComputerSystemPackage.Get()
}

func fetchCIMChassis(messages wsman.Messages) (any, error) {
	return messages.CIM.Chassis.Get()
}

func fetchCIMCard(messages wsman.Messages) (any, error) {
	return messages.CIM.Card.Get()
}

func fetchIPSScreenSettingData(messages wsman.Messages) (any, error) {
	return messages.IPS.ScreenSettingData.Get()
}

func fetchCIMSoftwareIdentity(messages wsman.Messages) (any, error) {
	enumerateResponse, err := messages.CIM.SoftwareIdentity.Enumerate()
	if err != nil {
		return nil, err
	}

	return messages.CIM.SoftwareIdentity.Pull(enumerateResponse.Body.EnumerateResponse.EnumerationContext)
}

func fetchCIMKVMRedirectionSAP(messages wsman.Messages) (any, error) {
	return messages.CIM.KVMRedirectionSAP.Get()
}

func fetchCIMWiFiEndpoint(messages wsman.Messages) (any, error) {
	enumerateResponse, err := messages.CIM.WiFiEndpointSettings.Enumerate()
	if err != nil {
		return nil, err
	}

	return messages.CIM.WiFiEndpointSettings.Pull(enumerateResponse.Body.EnumerateResponse.EnumerationContext)
}

func fetchCIMWiFiEndpointSettings(messages wsman.Messages) (any, error) {
	enumerateResponse, err := messages.CIM.WiFiEndpointSettings.Enumerate()
	if err != nil {
		return nil, err
	}

	return messages.CIM.WiFiEndpointSettings.Pull(enumerateResponse.Body.EnumerateResponse.EnumerationContext)
}

func fetchCIMWiFiPort(messages wsman.Messages) (any, error) {
	enumerateResponse, err := messages.CIM.WiFiPort.Enumerate()
	if err != nil {
		return nil, err
	}

	return messages.CIM.WiFiPort.Pull(enumerateResponse.Body.EnumerateResponse.EnumerationContext)
}

func fetchIPSHostBasedSetupService(messages wsman.Messages) (any, error) {
	return messages.IPS.HostBasedSetupService.Get()
}

func fetchIPSIEEE8021xSettings(messages wsman.Messages) (any, error) {
	return messages.IPS.IEEE8021xSettings.Get()
}

func fetchIPSKVMRedirectionSettingData(messages wsman.Messages) (any, error) {
	return messages.IPS.KVMRedirectionSettingData.Get()
}

func fetchIPSOptInService(messages wsman.Messages) (any, error) {
	return messages.IPS.OptInService.Get()
}

func fetchIPSSecIOService(messages wsman.Messages) (any, error) {
	return messages.IPS.SecIOService.Get()
}

func fetchIPSHTTPProxyAccessPoint(messages wsman.Messages) (any, error) {
	enumerateResponse, err := messages.IPS.HTTPProxyAccessPointService.Enumerate()
	if err != nil {
		return nil, err
	}

	return messages.IPS.HTTPProxyAccessPointService.Pull(enumerateResponse.Body.EnumerateResponse.EnumerationContext)
}

func unsupportedClassFetcher(className, reason string) classFetcher {
	return func(messages wsman.Messages) (any, error) {
		return unsupportedClassData{
			Class:   className,
			Status:  "not_supported",
			Message: reason,
		}, nil
	}
}
