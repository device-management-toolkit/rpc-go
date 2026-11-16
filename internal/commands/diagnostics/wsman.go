/*********************************************************************
 * Copyright (c) Intel Corporation 2026
 * SPDX-License-Identifier: Apache-2.0
 *********************************************************************/

package diagnostics

import (
	"bytes"
	"context"
	cryptotls "crypto/tls"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"reflect"
	"sort"
	"strings"
	"text/tabwriter"
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
	for _, className := range SupportedWSMANClasses() {
		fmt.Println(className)
	}

	return nil
}

// WSManGetCmd retrieves WSMAN class data for diagnostics.
type WSManGetCmd struct {
	DiagnosticsBaseCmd

	Class  []string `help:"Specific WSMAN class to retrieve (repeatable)" name:"class" short:"c"`
	Output string   `help:"Output file path" name:"output" short:"o" default:"stdout"`
	Format string   `help:"Output format" name:"format" short:"f" enum:"json,xml,table" default:"json"`
	All    bool     `help:"Retrieve data for all available WSMAN classes" name:"all" short:"a"`

	wsmanUsername string `kong:"-"`
}

// wsmanFetchError reports classes that failed to retrieve; the output is still written.
type wsmanFetchError struct {
	failed int
	total  int
	last   error
}

func (err *wsmanFetchError) Error() string {
	return fmt.Sprintf("%d of %d WSMAN class(es) failed to retrieve: %v", err.failed, err.total, err.last)
}

func (err *wsmanFetchError) Unwrap() error {
	return err.last
}

type classFetcher func(messages wsman.Messages) (any, error)

type classResult struct {
	Class string `json:"class" xml:"class,attr"`
	Data  any    `json:"data" xml:"-"`
	XML   string `json:"-" xml:",cdata"`
}

type classFetchErrorData struct {
	Class   string `json:"class" xml:"Class"`
	Status  string `json:"status" xml:"Status"`
	Message string `json:"message" xml:"Message"`
}

type rawWSMANClassData struct {
	Class       string `json:"class" xml:"Class"`
	ResourceURI string `json:"resourceUri" xml:"ResourceURI"`
	XMLOutput   string `json:"xmlOutput" xml:"XMLOutput"`
}

type xmlResults struct {
	XMLName xml.Name      `xml:"WSMANClasses"`
	Items   []classResult `xml:"Class"`
}

var wsmanClassFetchers = map[string]classFetcher{
	"AMT_8021XProfile":                    fetchAMT8021XProfile,
	"AMT_AssetTable":                      fetchAMTAssetTable,
	"AMT_AssetTableService":               fetchAMTAssetTableService,
	"AMT_AuditLog":                        fetchAMTAuditLog,
	"AMT_BootCapabilities":                fetchAMTBootCapabilities,
	"AMT_BootSettingData":                 fetchAMTBootSettingData,
	"AMT_CryptographicCapabilities":       fetchAMTCryptographicCapabilities,
	"AMT_EnvironmentDetectionSettingData": fetchAMTEnvironmentDetectionSettingData,
	"AMT_EventLogEntry":                   fetchAMTEventLogEntry,
	"AMT_EthernetPortSettings":            fetchAMTEthernetPortSettings,
	"AMT_GeneralSettings":                 fetchAMTGeneralSettings,
	"AMT_Hdr8021Filter":                   fetchAMTHdr8021Filter,
	"AMT_ManagementPresenceRemoteSAP":     fetchAMTManagementPresenceRemoteSAP,
	"AMT_MessageLog":                      fetchAMTMessageLog,
	"AMT_RedirectionService":              fetchAMTRedirectionService,
	"AMT_RemoteAccessCapabilities":        fetchAMTRemoteAccessCapabilities,
	"AMT_RemoteAccessPolicyAppliesToMPS":  fetchAMTRemoteAccessPolicyAppliesToMPS,
	"AMT_RemoteAccessPolicyRule":          fetchAMTRemoteAccessPolicyRule,
	"AMT_SetupAndConfigurationService":    fetchAMTSetupAndConfigurationService,
	"AMT_SystemPowerScheme":               fetchAMTSystemPowerScheme,
	"AMT_TimeSynchronizationService":      fetchAMTTimeSynchronizationService,
	"AMT_UserInitiatedConnectionService":  fetchAMTUserInitiatedConnectionService,
	"AMT_WiFiPortConfigurationService":    fetchAMTWiFiPortConfigurationService,
	"CIM_BIOSFeature":                     fetchCIMBIOSFeature,
	"CIM_BIOSElement":                     fetchCIMBIOSElement,
	"CIM_Card":                            fetchCIMCard,
	"CIM_Chassis":                         fetchCIMChassis,
	"CIM_ComputerSystemPackage":           fetchCIMComputerSystemPackage,
	"CIM_EthernetPort":                    fetchCIMEthernetPort,
	"CIM_KVMRedirectionSAP":               fetchCIMKVMRedirectionSAP,
	"CIM_PowerManagementCapabilities":     fetchCIMPowerManagementCapabilities,
	"CIM_PowerManagementService":          fetchCIMPowerManagementService,
	"CIM_Processor":                       fetchCIMProcessor,
	"CIM_RedirectionService":              fetchCIMRedirectionService,
	"CIM_SoftwareIdentity":                fetchCIMSoftwareIdentity,
	"CIM_WiFiEndpoint":                    fetchCIMWiFiEndpoint,
	"CIM_WiFiEndpointCapabilities":        fetchCIMWiFiEndpointCapabilities,
	"CIM_WiFiEndpointSettings":            fetchCIMWiFiEndpointSettings,
	"CIM_WiFiPort":                        fetchCIMWiFiPort,
	"CIM_WiFiPortCapabilities":            fetchCIMWiFiPortCapabilities,
	"IPS_HostBasedSetupService":           fetchIPSHostBasedSetupService,
	"IPS_HostBootReason":                  fetchIPSHostBootReason,
	"IPS_HostIPSettings":                  fetchIPSHostIPSettings,
	"IPS_HTTPProxyAccessPoint":            fetchIPSHTTPProxyAccessPoint,
	"IPS_IEEE8021xSettings":               fetchIPSIEEE8021xSettings,
	"IPS_IPv6PortSettings":                fetchIPSIPv6PortSettings,
	"IPS_KVMRedirectionSettingData":       fetchIPSKVMRedirectionSettingData,
	"IPS_LANEndpoint":                     fetchIPSLANEndpoint,
	"IPS_OptInService":                    fetchIPSOptInService,
	"IPS_ProvisioningRecordLog":           fetchIPSProvisioningRecordLog,
	"IPS_ScreenSettingData":               fetchIPSScreenSettingData,
	"IPS_SecIOService":                    fetchIPSSecIOService,
}

// Run executes the WSMAN get command.
func (cmd *WSManGetCmd) Run(ctx *commands.Context) error {
	err := cmd.collect(ctx)

	// Per-class failures are already recorded in the rendered output.
	var fetchErr *wsmanFetchError
	if errors.As(err, &fetchErr) {
		return nil
	}

	return err
}

// collect writes the selected classes and returns *wsmanFetchError when any class fails.
func (cmd *WSManGetCmd) collect(ctx *commands.Context) error {
	classes, err := cmd.Fetch(ctx)

	var fetchFailure *wsmanFetchError
	if err != nil && !errors.As(err, &fetchFailure) {
		return err
	}

	rendered, renderErr := RenderWSMANClasses(classes, strings.ToLower(strings.TrimSpace(cmd.Format)))
	if renderErr != nil {
		return renderErr
	}

	if strings.EqualFold(strings.TrimSpace(cmd.Output), "stdout") {
		fmt.Println(string(rendered))

		return err
	}

	outputPath := strings.TrimSpace(cmd.Output)

	if err := ensureParentDir(outputPath); err != nil {
		return err
	}

	if writeErr := os.WriteFile(outputPath, rendered, 0o644); writeErr != nil {
		return fmt.Errorf("failed to write output file: %w", writeErr)
	}

	if !cmd.quiet {
		fmt.Printf("WSMAN class data written to %s\n", outputPath)
	}

	return err
}

// WSMANClassData is one WSMAN class read by WSManGetCmd.Fetch: its data, or
// the error that kept it from being read.
type WSMANClassData struct {
	// Class is the WSMAN class name.
	Class string
	// Data is the go-wsman-messages response for the class; nil when Err is set.
	Data any
	// Err is why the class could not be read; nil when it was read.
	Err error
}

// Fetch reads the selected classes over WSMAN, the data collect renders. It
// returns every selected class with its data or its error. A non-nil result
// with an error means class reads failed: the error is the class's own error
// when one class was selected, otherwise a *wsmanFetchError. Fetch closes the
// connections it opens.
func (cmd *WSManGetCmd) Fetch(ctx *commands.Context) ([]WSMANClassData, error) {
	selectedClasses, err := cmd.ResolveClasses()
	if err != nil {
		return nil, err
	}

	if err := cmd.ensureAMTPassword(ctx); err != nil {
		return nil, err
	}

	messages, transport := cmd.newWSMANMessages(ctx)
	defer closeWSMANClient(messages.Client, transport)

	classes := make([]WSMANClassData, 0, len(selectedClasses))

	var fetchFailure *wsmanFetchError

	for _, className := range selectedClasses {
		fetcher := wsmanClassFetchers[className]

		data, fetchErr := fetcher(messages)
		if fetchErr == nil {
			classes = append(classes, WSMANClassData{Class: className, Data: data})

			continue
		}

		classes = append(classes, WSMANClassData{Class: className, Err: fetchErr})

		if len(selectedClasses) == 1 {
			return classes, fmt.Errorf("failed to retrieve WSMAN class %s: %w", className, fetchErr)
		}

		if cmd.quiet {
			log.Debugf("failed to retrieve WSMAN class %s: %v", className, fetchErr)
		} else {
			log.Warnf("failed to retrieve WSMAN class %s: %v", className, fetchErr)
		}

		if fetchFailure == nil {
			fetchFailure = &wsmanFetchError{total: len(selectedClasses)}
		}

		fetchFailure.failed++
		fetchFailure.last = fetchErr
	}

	return classes, fetchFailureOrNil(fetchFailure)
}

// RenderWSMANClasses renders classes in format (json, xml or table) as
// collect writes them; a class that could not be read is rendered as a
// fetch_failed entry.
func RenderWSMANClasses(classes []WSMANClassData, format string) ([]byte, error) {
	results := make([]classResult, 0, len(classes))

	for _, class := range classes {
		if class.Err != nil {
			results = append(results, classResult{Class: class.Class, Data: classFetchErrorData{
				Class:   class.Class,
				Status:  "fetch_failed",
				Message: class.Err.Error(),
			}})

			continue
		}

		results = append(results, classResult{Class: class.Class, Data: class.Data})
	}

	return renderResults(results, format)
}

// fetchFailureOrNil avoids returning a typed nil pointer as a non-nil error.
func fetchFailureOrNil(fetchFailure *wsmanFetchError) error {
	if fetchFailure == nil {
		return nil
	}

	return fetchFailure
}

// ResolveClasses returns the WSMAN classes the command reads: every supported
// class with --all, otherwise the --class values. It rejects both or neither,
// and unknown class names, with the CLI's messages.
func (cmd *WSManGetCmd) ResolveClasses() ([]string, error) {
	if cmd.All && len(cmd.Class) > 0 {
		return nil, fmt.Errorf("--all cannot be used with --class")
	}

	if !cmd.All && len(cmd.Class) == 0 {
		return nil, fmt.Errorf("specify --all or at least one --class")
	}

	if cmd.All {
		return SupportedWSMANClasses(), nil
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

func (cmd *WSManGetCmd) ensureAMTPassword(ctx *commands.Context) error {
	cmd.wsmanUsername = utils.AMTUserName

	if strings.TrimSpace(ctx.AMTPassword) != "" {
		return nil
	}

	if ctx.AMTCommand == nil {
		return fmt.Errorf("AMT command context is not initialized")
	}

	localAccount, err := ctx.AMTCommand.GetLocalSystemAccount()
	if err != nil {
		return fmt.Errorf("failed to retrieve local AMT credentials: %w", err)
	}

	if strings.TrimSpace(localAccount.Password) == "" {
		return fmt.Errorf("retrieved local AMT credentials do not contain a password")
	}

	if strings.TrimSpace(localAccount.Username) != "" {
		cmd.wsmanUsername = strings.TrimSpace(localAccount.Username)
	}

	ctx.AMTPassword = localAccount.Password

	return nil
}

// SupportedWSMANClasses returns the WSMAN class names `wsman list` prints.
func SupportedWSMANClasses() []string {
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
	case "table":
		return renderTableResults(results)
	default:
		return nil, fmt.Errorf("unsupported format: %s", format)
	}
}

type tableRow struct {
	key   string
	value string
}

type xmlNode struct {
	XMLName  xml.Name
	Children []xmlNode `xml:",any"`
	Content  string    `xml:",chardata"`
}

func renderTableResults(results []classResult) ([]byte, error) {
	var builder strings.Builder

	firstSection := true

	for _, result := range results {
		instances, err := extractClassInstances(result.Class, result.Data)
		if err != nil {
			return nil, fmt.Errorf("failed to render table for class %s: %w", result.Class, err)
		}

		if len(instances) == 0 {
			if !firstSection {
				builder.WriteString("\n")
			}

			_, _ = fmt.Fprintf(&builder, "No instances found for class: %s\n", result.Class)

			firstSection = false

			continue
		}

		for _, instance := range instances {
			if !firstSection {
				builder.WriteString("\n")
			}

			_, _ = fmt.Fprintf(&builder, "Class: %s\n", result.Class)

			var section bytes.Buffer

			writer := tabwriter.NewWriter(&section, 0, 8, 2, ' ', 0)

			_, _ = fmt.Fprintln(writer, "Name\tValue")
			for _, row := range instance {
				_, _ = fmt.Fprintf(writer, "%s\t%s\n", row.key, row.value)
			}

			_ = writer.Flush()

			builder.Write(section.Bytes())

			firstSection = false
		}
	}

	return []byte(builder.String()), nil
}

func extractClassInstances(className string, data any) ([][]tableRow, error) {
	if _, ok := data.(classFetchErrorData); ok {
		return nil, nil
	}

	if rawXML := extractXMLOutput(data); strings.TrimSpace(rawXML) != "" {
		var root xmlNode
		if err := xml.Unmarshal([]byte(rawXML), &root); err != nil {
			return nil, err
		}

		instances := make([][]tableRow, 0)
		collectClassInstances(root, className, &instances)

		return instances, nil
	}

	encoded, err := xml.Marshal(data)
	if err != nil {
		return nil, err
	}

	var root xmlNode
	if err := xml.Unmarshal(encoded, &root); err != nil {
		return nil, err
	}

	instances := make([][]tableRow, 0)
	collectClassInstances(root, className, &instances)

	return instances, nil
}

func collectClassInstances(node xmlNode, className string, instances *[][]tableRow) {
	if node.XMLName.Local == className {
		rows := make([]tableRow, 0, len(node.Children))
		for _, child := range node.Children {
			rows = append(rows, tableRow{
				key:   child.XMLName.Local,
				value: strings.TrimSpace(nodeInnerText(child)),
			})
		}

		*instances = append(*instances, rows)
	}

	for _, child := range node.Children {
		collectClassInstances(child, className, instances)
	}
}

func nodeInnerText(node xmlNode) string {
	if len(node.Children) == 0 {
		return strings.TrimSpace(node.Content)
	}

	parts := make([]string, 0, len(node.Children))
	for _, child := range node.Children {
		value := strings.TrimSpace(nodeInnerText(child))
		if value == "" {
			continue
		}

		parts = append(parts, value)
	}

	return strings.Join(parts, ",")
}

func extractXMLOutput(data any) string {
	v := reflect.ValueOf(data)
	if !v.IsValid() {
		return ""
	}

	if v.Kind() == reflect.Ptr {
		if v.IsNil() {
			return ""
		}

		v = v.Elem()
	}

	if v.Kind() != reflect.Struct {
		return ""
	}

	field := v.FieldByName("XMLOutput")
	if !field.IsValid() || field.Kind() != reflect.String {
		return ""
	}

	return field.String()
}

// lmeTransport is the transport newWSMANMessages falls back to when no LMS
// listens: it reaches AMT over LME and holds the MEI device until closed.
type lmeTransport interface {
	http.RoundTripper
	Close() error
}

// newLMETransport opens the LME fallback transport; tests replace it.
var newLMETransport = func() lmeTransport { return localamt.NewLocalTransport() }

// closeWSMANClient releases what newWSMANMessages opened: the client's TCP
// connection, its idle keep-alive connections to LMS and the LME transport,
// which would otherwise keep the MEI device open after Fetch returns.
func closeWSMANClient(wsmanClient interface{ CloseConnection() error }, transport lmeTransport) {
	if wsmanClient != nil {
		if closeErr := wsmanClient.CloseConnection(); closeErr != nil {
			log.Debugf("failed to close WSMAN client connection: %v", closeErr)
		}

		if idle, ok := wsmanClient.(interface{ CloseIdleConnections() }); ok {
			idle.CloseIdleConnections()
		}
	}

	if transport != nil {
		if closeErr := transport.Close(); closeErr != nil {
			log.Debugf("failed to close LME transport: %v", closeErr)
		}
	}
}

// newWSMANMessages builds the WSMAN client. The returned transport is the LME
// fallback it opened, or nil; the caller closes both with closeWSMANClient.
func (cmd *WSManGetCmd) newWSMANMessages(ctx *commands.Context) (wsman.Messages, lmeTransport) {
	var transport lmeTransport

	tlsConfig := certs.GetTLSConfig(&cmd.ControlMode, nil, ctx.SkipAMTCertCheck, nil)

	clientParams := client.Parameters{
		Target:         utils.LMSAddress,
		Username:       cmd.wsmanUsername,
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
			transport = newLMETransport()
			clientParams.Transport = transport
		} else {
			_ = conn.Close()
		}
	}

	return wsman.NewMessages(clientParams), transport
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

func fetchAMTAssetTable(messages wsman.Messages) (any, error) {
	enumerateResponse, err := messages.AMT.AssetTable.Enumerate()
	if err != nil {
		return nil, err
	}

	return messages.AMT.AssetTable.Pull(enumerateResponse.Body.EnumerateResponse.EnumerationContext)
}

func fetchAMTAssetTableService(messages wsman.Messages) (any, error) {
	enumerateResponse, err := messages.AMT.AssetTableService.Enumerate()
	if err != nil {
		return nil, err
	}

	return messages.AMT.AssetTableService.Pull(enumerateResponse.Body.EnumerateResponse.EnumerationContext)
}

func fetchAMTBootCapabilities(messages wsman.Messages) (any, error) {
	return messages.AMT.BootCapabilities.Get()
}

func fetchAMTBootSettingData(messages wsman.Messages) (any, error) {
	return messages.AMT.BootSettingData.Get()
}

func fetchAMTCryptographicCapabilities(messages wsman.Messages) (any, error) {
	enumerateResponse, err := messages.AMT.CryptographicCapabilities.Enumerate()
	if err != nil {
		return nil, err
	}

	return messages.AMT.CryptographicCapabilities.Pull(enumerateResponse.Body.EnumerateResponse.EnumerationContext)
}

func fetchAMTEnvironmentDetectionSettingData(messages wsman.Messages) (any, error) {
	return messages.AMT.EnvironmentDetectionSettingData.Get()
}

func fetchAMTEventLogEntry(messages wsman.Messages) (any, error) {
	enumerateResponse, err := messages.AMT.EventLogEntry.Enumerate()
	if err != nil {
		return nil, err
	}

	return messages.AMT.EventLogEntry.Pull(enumerateResponse.Body.EnumerateResponse.EnumerationContext)
}

func fetchAMTMessageLog(messages wsman.Messages) (any, error) {
	enumerateResponse, err := messages.AMT.MessageLog.Enumerate()
	if err != nil {
		return nil, err
	}

	return messages.AMT.MessageLog.Pull(enumerateResponse.Body.EnumerateResponse.EnumerationContext)
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

func fetchAMTHdr8021Filter(messages wsman.Messages) (any, error) {
	enumerateResponse, err := messages.AMT.Hdr8021Filter.Enumerate()
	if err != nil {
		return nil, err
	}

	return messages.AMT.Hdr8021Filter.Pull(enumerateResponse.Body.EnumerateResponse.EnumerationContext)
}

func fetchAMTRemoteAccessCapabilities(messages wsman.Messages) (any, error) {
	enumerateResponse, err := messages.AMT.RemoteAccessCapabilities.Enumerate()
	if err != nil {
		return nil, err
	}

	return messages.AMT.RemoteAccessCapabilities.Pull(enumerateResponse.Body.EnumerateResponse.EnumerationContext)
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

func fetchAMTUserInitiatedConnectionService(messages wsman.Messages) (any, error) {
	return messages.AMT.UserInitiatedConnectionService.Get()
}

func fetchAMTSystemPowerScheme(messages wsman.Messages) (any, error) {
	enumerateResponse, err := messages.AMT.SystemPowerScheme.Enumerate()
	if err != nil {
		return nil, err
	}

	return messages.AMT.SystemPowerScheme.Pull(enumerateResponse.Body.EnumerateResponse.EnumerationContext)
}

func fetchAMTTimeSynchronizationService(messages wsman.Messages) (any, error) {
	enumerateResponse, err := messages.AMT.TimeSynchronizationService.Enumerate()
	if err != nil {
		return nil, err
	}

	return messages.AMT.TimeSynchronizationService.Pull(enumerateResponse.Body.EnumerateResponse.EnumerationContext)
}

func fetchAMTWiFiPortConfigurationService(messages wsman.Messages) (any, error) {
	enumerateResponse, err := messages.AMT.WiFiPortConfigurationService.Enumerate()
	if err != nil {
		return nil, err
	}

	return messages.AMT.WiFiPortConfigurationService.Pull(enumerateResponse.Body.EnumerateResponse.EnumerationContext)
}

func fetchCIMBIOSFeature(messages wsman.Messages) (any, error) {
	enumerateResponse, err := messages.CIM.BIOSFeature.Enumerate()
	if err != nil {
		return nil, err
	}

	return messages.CIM.BIOSFeature.Pull(enumerateResponse.Body.EnumerateResponse.EnumerationContext)
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

func fetchCIMEthernetPort(messages wsman.Messages) (any, error) {
	enumerateResponse, err := messages.CIM.EthernetPort.Enumerate()
	if err != nil {
		return nil, err
	}

	return messages.CIM.EthernetPort.Pull(enumerateResponse.Body.EnumerateResponse.EnumerationContext)
}

func fetchCIMPowerManagementCapabilities(messages wsman.Messages) (any, error) {
	enumerateResponse, err := messages.CIM.PowerManagementCapabilities.Enumerate()
	if err != nil {
		return nil, err
	}

	return messages.CIM.PowerManagementCapabilities.Pull(enumerateResponse.Body.EnumerateResponse.EnumerationContext)
}

func fetchCIMRedirectionService(messages wsman.Messages) (any, error) {
	enumerateResponse, err := messages.CIM.RedirectionService.Enumerate()
	if err != nil {
		return nil, err
	}

	return messages.CIM.RedirectionService.Pull(enumerateResponse.Body.EnumerateResponse.EnumerationContext)
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
	enumerateResponse, err := messages.CIM.WiFiEndpoint.Enumerate()
	if err != nil {
		return nil, err
	}

	return messages.CIM.WiFiEndpoint.Pull(enumerateResponse.Body.EnumerateResponse.EnumerationContext)
}

func fetchCIMWiFiEndpointCapabilities(messages wsman.Messages) (any, error) {
	enumerateResponse, err := messages.CIM.WiFiEndpointCapabilities.Enumerate()
	if err != nil {
		return nil, err
	}

	return messages.CIM.WiFiEndpointCapabilities.Pull(enumerateResponse.Body.EnumerateResponse.EnumerationContext)
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

func fetchCIMWiFiPortCapabilities(messages wsman.Messages) (any, error) {
	enumerateResponse, err := messages.CIM.WiFiPortCapabilities.Enumerate()
	if err != nil {
		return nil, err
	}

	return messages.CIM.WiFiPortCapabilities.Pull(enumerateResponse.Body.EnumerateResponse.EnumerationContext)
}

func fetchIPSHostBasedSetupService(messages wsman.Messages) (any, error) {
	return messages.IPS.HostBasedSetupService.Get()
}

func fetchIPSIEEE8021xSettings(messages wsman.Messages) (any, error) {
	return messages.IPS.IEEE8021xSettings.Get()
}

func fetchIPSHostBootReason(messages wsman.Messages) (any, error) {
	enumerateResponse, err := messages.IPS.HostBootReason.Enumerate()
	if err != nil {
		return nil, err
	}

	return messages.IPS.HostBootReason.Pull(enumerateResponse.Body.EnumerateResponse.EnumerationContext)
}

func fetchIPSHostIPSettings(messages wsman.Messages) (any, error) {
	enumerateResponse, err := messages.IPS.HostIPSettings.Enumerate()
	if err != nil {
		return nil, err
	}

	return messages.IPS.HostIPSettings.Pull(enumerateResponse.Body.EnumerateResponse.EnumerationContext)
}

func fetchIPSIPv6PortSettings(messages wsman.Messages) (any, error) {
	enumerateResponse, err := messages.IPS.IPv6PortSettings.Enumerate()
	if err != nil {
		return nil, err
	}

	return messages.IPS.IPv6PortSettings.Pull(enumerateResponse.Body.EnumerateResponse.EnumerationContext)
}

func fetchIPSLANEndpoint(messages wsman.Messages) (any, error) {
	enumerateResponse, err := messages.IPS.LANEndpoint.Enumerate()
	if err != nil {
		return nil, err
	}

	return messages.IPS.LANEndpoint.Pull(enumerateResponse.Body.EnumerateResponse.EnumerationContext)
}

func fetchIPSProvisioningRecordLog(messages wsman.Messages) (any, error) {
	enumerateResponse, err := messages.IPS.ProvisioningRecordLog.Enumerate()
	if err != nil {
		return nil, err
	}

	return messages.IPS.ProvisioningRecordLog.Pull(enumerateResponse.Body.EnumerateResponse.EnumerationContext)
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
