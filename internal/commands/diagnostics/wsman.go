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
	"fmt"
	"html"
	"net"
	"os"
	"path/filepath"
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
	"github.com/google/uuid"
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
	Format string   `help:"Output format" name:"format" short:"f" enum:"json,xml,table" default:"json"`
	All    bool     `help:"Retrieve data for all available WSMAN classes" name:"all" short:"a"`

	wsmanUsername string `kong:"-"`
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
	"AMT_AssetTable":                      rawWSMANClassFetcher("AMT_AssetTable"),
	"AMT_AssetTableService":               rawWSMANClassFetcher("AMT_AssetTableService"),
	"AMT_AuditLog":                        fetchAMTAuditLog,
	"AMT_BootCapabilities":                fetchAMTBootCapabilities,
	"AMT_BootSettingData":                 fetchAMTBootSettingData,
	"AMT_CryptographicCapabilities":       rawWSMANClassFetcher("AMT_CryptographicCapabilities"),
	"AMT_EnvironmentDetectionSettingData": fetchAMTEnvironmentDetectionSettingData,
	"AMT_EventLogEntry":                   rawWSMANClassFetcher("AMT_EventLogEntry"),
	"AMT_EthernetPortSettings":            fetchAMTEthernetPortSettings,
	"AMT_GeneralSettings":                 fetchAMTGeneralSettings, //nolint:goconst // WSMAN class name; remaining occurrences are in tests
	"AMT_Hdr8021Filter":                   rawWSMANClassFetcher("AMT_Hdr8021Filter"),
	"AMT_ManagementPresenceRemoteSAP":     fetchAMTManagementPresenceRemoteSAP,
	"AMT_MessageLog":                      fetchAMTMessageLog,
	"AMT_RedirectionService":              fetchAMTRedirectionService,
	"AMT_RemoteAccessCapabilities":        rawWSMANClassFetcher("AMT_RemoteAccessCapabilities"),
	"AMT_RemoteAccessPolicyAppliesToMPS":  fetchAMTRemoteAccessPolicyAppliesToMPS,
	"AMT_RemoteAccessPolicyRule":          fetchAMTRemoteAccessPolicyRule,
	"AMT_SetupAndConfigurationService":    fetchAMTSetupAndConfigurationService,
	"AMT_SystemPowerScheme":               rawWSMANClassFetcher("AMT_SystemPowerScheme"),
	"AMT_TimeSynchronizationService":      rawWSMANClassFetcher("AMT_TimeSynchronizationService"),
	"AMT_UserInitiatedConnectionService":  fetchAMTUserInitiatedConnectionService,
	"AMT_WiFiPortConfigurationService":    rawWSMANClassFetcher("AMT_WiFiPortConfigurationService"),
	"CIM_BIOSFeature":                     rawWSMANClassFetcher("CIM_BIOSFeature"),
	"CIM_BIOSElement":                     fetchCIMBIOSElement,
	"CIM_Card":                            fetchCIMCard,
	"CIM_Chassis":                         fetchCIMChassis,
	"CIM_ComputerSystemPackage":           fetchCIMComputerSystemPackage,
	"CIM_EthernetPort":                    rawWSMANClassFetcher("CIM_EthernetPort"),
	"CIM_KVMRedirectionSAP":               fetchCIMKVMRedirectionSAP,
	"CIM_PowerManagementCapabilities":     rawWSMANClassFetcher("CIM_PowerManagementCapabilities"),
	"CIM_PowerManagementService":          fetchCIMPowerManagementService,
	"CIM_Processor":                       fetchCIMProcessor,
	"CIM_RedirectionService":              rawWSMANClassFetcher("CIM_RedirectionService"),
	"CIM_SoftwareIdentity":                fetchCIMSoftwareIdentity,
	"CIM_WiFiEndpoint":                    rawWSMANClassFetcher("CIM_WiFiEndpoint"),
	"CIM_WiFiEndpointCapabilities":        rawWSMANClassFetcher("CIM_WiFiEndpointCapabilities"),
	"CIM_WiFiEndpointSettings":            rawWSMANClassFetcher("CIM_WiFiEndpointSettings"),
	"CIM_WiFiPort":                        rawWSMANClassFetcher("CIM_WiFiPort"),
	"CIM_WiFiPortCapabilities":            rawWSMANClassFetcher("CIM_WiFiPortCapabilities"),
	"IPS_HostBasedSetupService":           fetchIPSHostBasedSetupService,
	"IPS_HostBootReason":                  rawWSMANClassFetcher("IPS_HostBootReason"),
	"IPS_HostIPSettings":                  rawWSMANClassFetcher("IPS_HostIPSettings"),
	"IPS_HTTPProxyAccessPoint":            fetchIPSHTTPProxyAccessPoint,
	"IPS_IEEE8021xSettings":               fetchIPSIEEE8021xSettings,
	"IPS_IPv6PortSettings":                rawWSMANClassFetcher("IPS_IPv6PortSettings"),
	"IPS_KVMRedirectionSettingData":       fetchIPSKVMRedirectionSettingData,
	"IPS_LANEndpoint":                     rawWSMANClassFetcher("IPS_LANEndpoint"),
	"IPS_OptInService":                    fetchIPSOptInService,
	"IPS_ProvisioningRecordLog":           rawWSMANClassFetcher("IPS_ProvisioningRecordLog"),
	"IPS_ScreenSettingData":               fetchIPSScreenSettingData,
	"IPS_SecIOService":                    fetchIPSSecIOService,
}

// Run executes the WSMAN get command.
func (cmd *WSManGetCmd) Run(ctx *commands.Context) error {
	selectedClasses, err := cmd.resolveClasses()
	if err != nil {
		return err
	}

	if err := cmd.ensureAMTPassword(ctx); err != nil {
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

func (cmd *WSManGetCmd) newWSMANMessages(ctx *commands.Context) (wsman.Messages, error) {
	tlsConfig := certs.GetTLSConfig(&cmd.ControlMode, nil, ctx.SkipAMTCertCheck)

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

func rawWSMANClassFetcher(className string) classFetcher {
	return func(messages wsman.Messages) (any, error) {
		resourceURI, err := classResourceURI(className)
		if err != nil {
			return nil, err
		}

		enumerationContext, err := wsmanEnumerate(messages, resourceURI)
		if err != nil {
			return nil, err
		}

		pullXML, err := wsmanPull(messages, resourceURI, enumerationContext)
		if err != nil {
			return nil, err
		}

		return rawWSMANClassData{
			Class:       className,
			ResourceURI: resourceURI,
			XMLOutput:   pullXML,
		}, nil
	}
}

func classResourceURI(className string) (string, error) {
	switch {
	case strings.HasPrefix(className, "AMT_"):
		return "http://intel.com/wbem/wscim/1/amt-schema/1/" + className, nil
	case strings.HasPrefix(className, "CIM_"):
		return "http://schemas.dmtf.org/wbem/wscim/1/cim-schema/2/" + className, nil
	case strings.HasPrefix(className, "IPS_"):
		return "http://intel.com/wbem/wscim/1/ips-schema/1/" + className, nil
	default:
		return "", fmt.Errorf("unsupported class prefix for %s", className)
	}
}

func wsmanEnumerate(messages wsman.Messages, resourceURI string) (string, error) {
	toAddress := wsmanEndpoint(messages)
	envelope := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?><soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope" xmlns:tns="%s" xmlns:wsman="http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd" xmlns:wsa="http://schemas.xmlsoap.org/ws/2004/08/addressing" xmlns:wsen="http://schemas.xmlsoap.org/ws/2004/09/enumeration"><soap:Header><wsa:To>%s</wsa:To><wsa:ReplyTo><wsa:Address soap:mustUnderstand="true">http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous</wsa:Address></wsa:ReplyTo><wsa:Action soap:mustUnderstand="true">http://schemas.xmlsoap.org/ws/2004/09/enumeration/Enumerate</wsa:Action><wsman:MaxEnvelopeSize soap:mustUnderstand="true">51200</wsman:MaxEnvelopeSize><wsa:MessageID>uuid:%s</wsa:MessageID><wsman:ResourceURI soap:mustUnderstand="true">%s</wsman:ResourceURI><wsman:OperationTimeout>PT60.000S</wsman:OperationTimeout></soap:Header><soap:Body><wsen:Enumerate /></soap:Body></soap:Envelope>`, resourceURI, toAddress, uuid.NewString(), resourceURI)

	response, err := messages.Client.Post(envelope)
	if err != nil {
		return "", err
	}

	var root xmlNode
	if err := xml.Unmarshal(response, &root); err != nil {
		return "", err
	}

	node := findFirstNodeByLocalName(root, "EnumerationContext")
	if node == nil {
		return "", fmt.Errorf("enumeration context not found in response")
	}

	enumerationContext := strings.TrimSpace(nodeInnerText(*node))
	if enumerationContext == "" {
		return "", fmt.Errorf("empty enumeration context in response")
	}

	return enumerationContext, nil
}

func wsmanPull(messages wsman.Messages, resourceURI, enumerationContext string) (string, error) {
	escapedContext := html.EscapeString(enumerationContext)
	toAddress := wsmanEndpoint(messages)
	envelope := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?><soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope" xmlns:tns="%s" xmlns:wsman="http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd" xmlns:wsa="http://schemas.xmlsoap.org/ws/2004/08/addressing" xmlns:wsen="http://schemas.xmlsoap.org/ws/2004/09/enumeration"><soap:Header><wsa:To>%s</wsa:To><wsa:ReplyTo><wsa:Address soap:mustUnderstand="true">http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous</wsa:Address></wsa:ReplyTo><wsa:Action soap:mustUnderstand="true">http://schemas.xmlsoap.org/ws/2004/09/enumeration/Pull</wsa:Action><wsman:MaxEnvelopeSize soap:mustUnderstand="true">51200</wsman:MaxEnvelopeSize><wsa:MessageID>uuid:%s</wsa:MessageID><wsman:ResourceURI soap:mustUnderstand="true">%s</wsman:ResourceURI><wsman:OperationTimeout>PT60.000S</wsman:OperationTimeout></soap:Header><soap:Body><wsen:Pull><wsen:EnumerationContext>%s</wsen:EnumerationContext><wsen:MaxElements>101</wsen:MaxElements></wsen:Pull></soap:Body></soap:Envelope>`, resourceURI, toAddress, uuid.NewString(), resourceURI, escapedContext)

	response, err := messages.Client.Post(envelope)
	if err != nil {
		return "", err
	}

	return string(response), nil
}

func findFirstNodeByLocalName(node xmlNode, localName string) *xmlNode {
	if node.XMLName.Local == localName {
		matched := node

		return &matched
	}

	for _, child := range node.Children {
		matched := findFirstNodeByLocalName(child, localName)
		if matched != nil {
			return matched
		}
	}

	return nil
}

func wsmanEndpoint(messages wsman.Messages) string {
	target, ok := messages.Client.(*client.Target)
	if !ok {
		return "/wsman"
	}

	value := reflect.ValueOf(target)
	if value.Kind() == reflect.Pointer {
		value = value.Elem()
	}

	endpointField := value.FieldByName("endpoint")
	if endpointField.IsValid() && endpointField.Kind() == reflect.String {
		if endpoint := endpointField.String(); endpoint != "" {
			return endpoint
		}
	}

	return "/wsman"
}
