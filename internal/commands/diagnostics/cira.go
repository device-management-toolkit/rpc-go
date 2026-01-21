/*********************************************************************
 * Copyright (c) Intel Corporation 2026
 * SPDX-License-Identifier: Apache-2.0
 *********************************************************************/

package diagnostics

import (
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"text/template"
	"time"

	"github.com/device-management-toolkit/rpc-go/v2/internal/commands"
	"github.com/device-management-toolkit/rpc-go/v2/pkg/pthi"
)

const (
	unknownValue = "Unknown"
	zeroIP       = "0.0.0.0"
)

// CIRACmd dumps CIRA-related firmware diagnostics.
type CIRACmd struct {
	DiagnosticsBaseCmd

	Output string `help:"Output file path for the CIRA log text data" short:"o"`
}

// Run executes the CIRA diagnostics command.
func (cmd *CIRACmd) Run(ctx *commands.Context) error {
	// Generate default filename if not provided
	if cmd.Output == "" {
		timestamp := time.Now().Format("20060102_150405")
		cmd.Output = fmt.Sprintf("%s_ciralog.txt", timestamp)
	}

	// Ensure output directory exists
	outputDir := filepath.Dir(cmd.Output)
	if outputDir != "." && outputDir != "" {
		if err := os.MkdirAll(outputDir, 0o755); err != nil {
			return fmt.Errorf("failed to create output directory: %w", err)
		}
	}

	// Get CIRA log from firmware
	result, err := ctx.AMTCommand.GetCiraLog()
	if err != nil {
		return err
	}

	// Create output file
	file, err := os.Create(cmd.Output)
	if err != nil {
		return fmt.Errorf("failed to create output file: %w", err)
	}
	defer file.Close()

	// Write CIRA log data to file
	outputCiraLogText(file, result)

	fmt.Printf("CIRA Log successfully retrieved\nOutput file: %s\n", cmd.Output)

	return nil
}

func outputCiraLogText(w io.Writer, result pthi.GetCiraLogResponse) {
	t := template.New("ciraLog").Funcs(template.FuncMap{
		"getConnectionStateString":      getConnectionStateString,
		"formatTimestamp":               formatTimestamp,
		"getLastConnectionStatusString": getLastConnectionStatusString,
		"getLastTunnelStatusString":     getLastTunnelStatusString,
		"getConnectionTriggerString":    getConnectionTriggerString,
		"byteArrayToString":             byteArrayToString,
		"getAuthenticationMethodString": getAuthenticationMethodString,
		"getInterfaceTypeString":        getInterfaceTypeString,
		"getHostControlString":          getHostControlString,
		"getLinkStatusString":           getLinkStatusString,
		"getDhcpModeString":             getDhcpModeString,
		"formatIPv4":                    formatIPv4,
		"formatIPv6":                    formatIPv6,
		"getIPv6AddressTypeString":      getIPv6AddressTypeString,
		"getIPv6AddressStateString":     getIPv6AddressStateString,
		"getConnectionStatusString":     getConnectionStatusString,
		"getTcpFailureCodeString":       getTcpFailureCodeString,
		"getTlsFailureCodeString":       getTlsFailureCodeString,
		"getClosedByString":             getClosedByString,
		"getAPFDisconnectReasonString":  getAPFDisconnectReasonString,
		"getClosureReasonString":        getClosureReasonString,
		"getTunnelStatusString": func(opened uint8) string {
			if opened == 1 {
				return "Opened"
			}

			return "Closed"
		},
	})

	t, err := t.Parse(ciraLogTemplate)
	if err != nil {
		fmt.Fprintf(w, "Error parsing template: %v\n", err)

		return
	}

	err = t.Execute(w, result)
	if err != nil {
		fmt.Fprintf(w, "Error executing template: %v\n", err)
	}
}

const ciraLogTemplate = `Status = {{printf "%d" .Header.Status}} ({{.Header.Status}})
Version = {{.Version}}
CiraStatusSummary:
	IsTunnelOpened = {{.CiraStatusSummary.IsTunnelOpened}} ({{getTunnelStatusString .CiraStatusSummary.IsTunnelOpened}})
	CurrentConnectionState = {{.CiraStatusSummary.CurrentConnectionState}} ({{getConnectionStateString .CiraStatusSummary.CurrentConnectionState}})
	LastKeepAlive(The time in which the last keepalive message was sent, 0 if not currently connected) = {{.CiraStatusSummary.LastKeepAlive}}({{.CiraStatusSummary.LastKeepAlive | formatTimestamp}})
	KeepAliveInterval(AMT's keepalive interval in seconds, valid only if currently connected) = {{.CiraStatusSummary.KeepAliveInterval}}
	LastConnectionStatus = {{.CiraStatusSummary.LastConnectionStatus}} ({{getLastConnectionStatusString .CiraStatusSummary.LastConnectionStatus}})
	LastConnectionTimestamp = {{.CiraStatusSummary.LastConnectionTimestamp}} ({{.CiraStatusSummary.LastConnectionTimestamp | formatTimestamp}})
	LastTunnelStatus = {{.CiraStatusSummary.LastTunnelStatus}} ({{getLastTunnelStatusString .CiraStatusSummary.LastTunnelStatus}})
	LastTunnelOpenedTimestamp = {{.CiraStatusSummary.LastTunnelOpenedTimestamp}} ({{.CiraStatusSummary.LastTunnelOpenedTimestamp | formatTimestamp}})
	LastTunnelClosedTimestamp = {{.CiraStatusSummary.LastTunnelClosedTimestamp}} ({{.CiraStatusSummary.LastTunnelClosedTimestamp | formatTimestamp}})
LastFailedTunnelLogEntry:
	Valid = {{.LastFailedTunnelLogEntry.Valid}}
	OpenTimestamp = {{.LastFailedTunnelLogEntry.OpenTimestamp}} ({{.LastFailedTunnelLogEntry.OpenTimestamp | formatTimestamp}})
	RemoteAccessConnectionTrigger = {{.LastFailedTunnelLogEntry.RemoteAccessConnectionTrigger}} ({{getConnectionTriggerString .LastFailedTunnelLogEntry.RemoteAccessConnectionTrigger}})
	MpsHostname = {{byteArrayToString .LastFailedTunnelLogEntry.MpsHostname}}
	ProxyUsed(Indicates whether CIRA connection is over proxy) = {{.LastFailedTunnelLogEntry.ProxyUsed}}
	ProxyName = {{byteArrayToString .LastFailedTunnelLogEntry.ProxyName}}
	AuthenticationMethod = {{.LastFailedTunnelLogEntry.AuthenticationMethod}} ({{getAuthenticationMethodString .LastFailedTunnelLogEntry.AuthenticationMethod}})
	ConnectedInterface = {{.LastFailedTunnelLogEntry.ConnectedInterface}} ({{getInterfaceTypeString .LastFailedTunnelLogEntry.ConnectedInterface}})
	LastKeepAlive = {{.LastFailedTunnelLogEntry.LastKeepAlive}} ({{.LastFailedTunnelLogEntry.LastKeepAlive | formatTimestamp}})
	KeepAliveInterval = {{.LastFailedTunnelLogEntry.KeepAliveInterval}}
	TunnelClosureInfo:
		ClosureTimestamp = {{.LastFailedTunnelLogEntry.TunnelClosureInfo.ClosureTimestamp}} ({{.LastFailedTunnelLogEntry.TunnelClosureInfo.ClosureTimestamp | formatTimestamp}})
		ClosedBy = {{.LastFailedTunnelLogEntry.TunnelClosureInfo.ClosedByMps}} ({{getClosedByString .LastFailedTunnelLogEntry.TunnelClosureInfo.ClosedByMps}})
		APF_DISCONNECT_REASON = {{.LastFailedTunnelLogEntry.TunnelClosureInfo.APF_DISCONNECT_REASON}} ({{getAPFDisconnectReasonString .LastFailedTunnelLogEntry.TunnelClosureInfo.APF_DISCONNECT_REASON}})
		ClosureReason = {{.LastFailedTunnelLogEntry.TunnelClosureInfo.ClosureReason}} ({{getClosureReasonString .LastFailedTunnelLogEntry.TunnelClosureInfo.ClosureReason}})
FailedConnectionLogEntry:
	Valid = {{.FailedConnectionLogEntry.Valid}}
	OpenTimestamp = {{.FailedConnectionLogEntry.OpenTimestamp}} ({{.FailedConnectionLogEntry.OpenTimestamp | formatTimestamp}})
	RemoteAccessConnectionTrigger = {{.FailedConnectionLogEntry.RemoteAccessConnectionTrigger}} ({{getConnectionTriggerString .FailedConnectionLogEntry.RemoteAccessConnectionTrigger}})
	MpsHostname = {{byteArrayToString .FailedConnectionLogEntry.MpsHostname}}
	AuthenticationMethod = {{.FailedConnectionLogEntry.AuthenticationMethod}} ({{getAuthenticationMethodString .FailedConnectionLogEntry.AuthenticationMethod}})
	InterfaceData:
{{- range $i, $e := .FailedConnectionLogEntry.InterfaceData}}
		{{if eq $i 0}}Lan Item:{{else}}Wireless Item:{{end}}
			InterfacePresent = {{$e.InterfacePresent}}
			LinkStatus = {{$e.LinkStatus}} ({{getLinkStatusString $e.LinkStatus}})
			IPParameters:
				DhcpMode = {{$e.IPParameters.DhcpMode}} ({{getDhcpModeString $e.IPParameters.DhcpMode}})
				IpAddress = {{formatIPv4 $e.IPParameters.IpAddress}}
				DefaultGatewayAddress = {{formatIPv4 $e.IPParameters.DefaultGatewayAddress}}
				PrimaryDnsAddress = {{formatIPv4 $e.IPParameters.PrimaryDnsAddress}}
				SecondaryDnsAddress = {{formatIPv4 $e.IPParameters.SecondaryDnsAddress}}
				DomainName = {{byteArrayToString $e.IPParameters.DomainName}}
				IPv6DefaultRouter:
					Address = {{formatIPv6 $e.IPParameters.IPv6DefaultRouter}}
				PrimaryDNS:
					Address = {{formatIPv6 $e.IPParameters.PrimaryDNS}}
				SecondaryDNS:
					Address = {{formatIPv6 $e.IPParameters.SecondaryDNS}}
				IPv6Addresses:
{{- range $j, $addr := $e.IPParameters.IPv6Addresses}}
					Address = {{formatIPv6 $addr.Address}}
					Type = {{$addr.Type}} ({{getIPv6AddressTypeString $addr.Type}})
					State = {{$addr.State}} ({{getIPv6AddressStateString $addr.State}})
{{- end}}
{{- end}}
	WirelessAdditionalData:
		ProfileName = {{byteArrayToString .FailedConnectionLogEntry.WirelessAdditionalData.ProfileName}}
		HostControl = {{.FailedConnectionLogEntry.WirelessAdditionalData.HostControl}} ({{getHostControlString .FailedConnectionLogEntry.WirelessAdditionalData.HostControl}})
	WiredAdditionalData:
		802.1xAuthenticationResult = {{.FailedConnectionLogEntry.WiredAdditionalData.AuthResult802_1x}}
		802.1xAuthenticationSubResult = {{.FailedConnectionLogEntry.WiredAdditionalData.AuthSubResult802_1x}}
		WiredMediaType = {{.FailedConnectionLogEntry.WiredAdditionalData.WiredMediaType}}
		DiscreteLanStatus = {{.FailedConnectionLogEntry.WiredAdditionalData.DiscreteLanStatus}}
	ConnectedInterface = {{.FailedConnectionLogEntry.ConnectedInterface}} ({{getInterfaceTypeString .FailedConnectionLogEntry.ConnectedInterface}})
	ConnectionDetails:
{{- range $i, $e := .FailedConnectionLogEntry.ConnectionDetails}}
		{{if eq $i 0}}Lan Item:{{else}}Wireless Item:{{end}}
			ConnectionStatus = {{$e.ConnectionStatus}} ({{getConnectionStatusString $e.ConnectionStatus}})
			ProxyUsed = {{$e.ProxyUsed}}
			ProxyName = {{byteArrayToString $e.ProxyName}}
			TcpFailureCode = {{$e.TcpFailureCode}} ({{getTcpFailureCodeString $e.TcpFailureCode}})
			TlsFailureCode = {{$e.TlsFailureCode}} ({{getTlsFailureCodeString $e.TlsFailureCode}})
{{- end}}
	TunnelEstablishmentFailure:
		ClosureTimestamp = {{.FailedConnectionLogEntry.TunnelEstablishmentFailure.ClosureTimestamp}} ({{.FailedConnectionLogEntry.TunnelEstablishmentFailure.ClosureTimestamp | formatTimestamp}})
		ClosedBy = {{.FailedConnectionLogEntry.TunnelEstablishmentFailure.ClosedByMps}} ({{getClosedByString .FailedConnectionLogEntry.TunnelEstablishmentFailure.ClosedByMps}})
		APF_DISCONNECT_REASON = {{.FailedConnectionLogEntry.TunnelEstablishmentFailure.APF_DISCONNECT_REASON}} ({{getAPFDisconnectReasonString .FailedConnectionLogEntry.TunnelEstablishmentFailure.APF_DISCONNECT_REASON}})
		ClosureReason = {{.FailedConnectionLogEntry.TunnelEstablishmentFailure.ClosureReason}} ({{getClosureReasonString .FailedConnectionLogEntry.TunnelEstablishmentFailure.ClosureReason}})
`

// Helper functions
func byteArrayToString(data interface{}) string {
	var bytes []byte

	switch v := data.(type) {
	case [256]uint8:
		bytes = v[:]
	case [192]uint8:
		bytes = v[:]
	case [33]uint8:
		bytes = v[:]
	case []uint8:
		bytes = v
	default:
		return ""
	}

	// Find null terminator
	for i, b := range bytes {
		if b == 0 {
			return string(bytes[:i])
		}
	}

	// No null terminator found, return entire array
	return string(bytes)
}

func formatTimestamp(ts uint32) string {
	if ts == 0 {
		return "1970-01-01 00:00:00 UTC"
	}

	t := time.Unix(int64(ts), 0).UTC()

	return t.Format("2006-01-02 15:04:05") + " UTC"
}

func formatIPv4(ip uint32) string {
	if ip == 0 {
		return zeroIP
	}

	return net.IP([]byte{
		byte(ip),
		byte(ip >> 8),
		byte(ip >> 16),
		byte(ip >> 24),
	}).String()
}

func formatIPv6(addr pthi.IPv6Address) string {
	// Check if all bytes are zero
	allZero := true

	for _, b := range addr.Address {
		if b != 0 {
			allZero = false

			break
		}
	}

	if allZero {
		return ""
	}

	ip := net.IP(addr.Address[:])

	return ip.String()
}

var (
	connectionStates = map[uint8]string{
		0: "Inside Enterprise",
		1: "Inside Corporate Environment, outside Enterprise",
		2: "Outside Enterprise",
	}

	connectionTriggers = map[uint8]string{
		0: "User Initiated",
		1: "Alert",
		2: "Periodic",
	}

	interfaceTypes = map[uint8]string{
		0: "INTERFACE_TYPE_WIRED",
		1: "INTERFACE_TYPE_WIRELESS",
		2: "INTERFACE_TYPE_NONE",
	}

	dhcpModes = map[uint8]string{
		0: "None",
		1: "Disabled",
		2: "Enabled",
	}

	authMethods = map[uint8]string{
		1: "MutualTLS",
		2: "Username and password",
	}

	ipv6AddressTypes = map[uint8]string{
		0: "CFG_Ipv6_ADDR_TYPE_LINK_LOCAL",
		1: "CFG_Ipv6_ADDR_TYPE_GLOBAL",
		2: "CFG_Ipv6_ADDR_TYPE_STATELESS",
		3: "CFG_Ipv6_ADDR_TYPE_STATEFUL",
	}

	ipv6AddressStates = map[uint8]string{
		0: "CFG_Ipv6_ADDR_STATE_TENTATIVE",
		1: "CFG_Ipv6_ADDR_STATE_PREFERRED",
		2: "CFG_Ipv6_ADDR_STATE_DEPRECATED",
	}

	connectionStatuses = map[uint32]string{
		0: "CIRA_LOG_CONNECTION_STATUS_NA",
		1: "CIRA_LOG_CONNECTION_STATUS_INTERNAL_ERROR",
		2: "CIRA_LOG_CONNECTION_STATUS_ERROR_DNS",
		3: "CIRA_LOG_CONNECTION_STATUS_ERROR_TCP",
		4: "CIRA_LOG_CONNECTION_STATUS_ERROR_TLS",
		5: "CIRA_LOG_CONNECTION_STATUS_SUCCESS",
		6: "CIRA_LOG_CONNECTION_STATUS_IN_PROGRESS",
	}

	tcpFailureCodes = map[uint32]string{
		0: "CIRA_LOGGER_TCP_ERR_SUCCESS",
		1: "CIRA_LOGGER_TCP_ERR_GENERAL_FAILURE",
		2: "CIRA_LOGGER_TCP_ERR_TIMED_OUT",
		3: "CIRA_LOGGER_TCP_ERR_CONNECTION_RESET",
		4: "CIRA_LOGGER_TCP_ERR_DESTINATION_UNREACHABLE",
	}

	apfDisconnectReasons = map[uint8]string{
		0:  "APF_DISCONNECT_INVALID_REASON_CODE",
		1:  "APF_DISCONNECT_HOST_NOT_ALLOWED_TO_CONNECT",
		2:  "APF_DISCONNECT_PROTOCOL_ERROR",
		3:  "APF_DISCONNECT_KEY_EXCHANGE_FAILED",
		4:  "APF_DISCONNECT_RESERVED",
		5:  "APF_DISCONNECT_MAC_ERROR",
		6:  "APF_DISCONNECT_COMPRESSION_ERROR",
		7:  "APF_DISCONNECT_SERVICE_NOT_AVAILABLE",
		8:  "APF_DISCONNECT_PROTOCOL_VERSION_NOT_SUPPORTED",
		9:  "APF_DISCONNECT_HOST_KEY_NOT_VERIFIABLE",
		10: "APF_DISCONNECT_CONNECTION_LOST",
		11: "APF_DISCONNECT_BY_APPLICATION",
		12: "APF_DISCONNECT_TOO_MANY_CONNECTIONS",
		13: "APF_DISCONNECT_AUTH_CANCELED_BY_USER",
		14: "APF_DISCONNECT_NO_MORE_AUTH_METHODS_AVAILABLE",
		15: "APF_DISCONNECT_ILLEGAL_USER_NAME",
		16: "APF_DISCONNECT_CONNECTION_TIMED_OUT",
	}

	closureReasons = map[uint8]string{
		0:    "AMT_CLOSE_REASON_USER_INITIATE_REQUEST",
		1:    "AMT_CLOSE_REASON_TUNNEL_TIMER_EXPIRED",
		2:    "AMT_CLOSE_REASON_INTERNAL_ERROR",
		3:    "AMT_CLOSE_REASON_KEEP_ALIVE_EXPIRED",
		4:    "AMT_CLOSE_REASON_TCP_SOCKET_ERROR",
		5:    "AMT_CLOSE_REASON_INVALID_APF_COMMAND",
		0xFF: "AMT_CLOSE_REASON_NA",
	}

	hostControls = map[uint8]string{
		0: "AMT",
		1: "Host",
	}

	closedByEntities = map[uint8]string{
		0: "AMT",
		1: "MPS",
	}

	linkStatuses = map[uint8]string{
		0: "Down",
		1: "Up",
	}

	tlsFailureCodes = map[int32]string{
		0:   "close_notify",
		10:  "unexpected_message",
		20:  "bad_record_mac",
		21:  "decryption_failed_RESERVED",
		22:  "record_overflow",
		30:  "decompression_failure_RESERVED",
		40:  "handshake_failure",
		41:  "no_certificate_RESERVED",
		42:  "bad_certificate",
		43:  "unsupported_certificate",
		44:  "certificate_revoked",
		45:  "certificate_expired",
		46:  "certificate_unknown",
		47:  "illegal_parameter",
		48:  "unknown_ca",
		49:  "access_denied",
		50:  "decode_error",
		51:  "decrypt_error",
		60:  "export_restriction_RESERVED",
		70:  "protocol_version",
		71:  "insufficient_security",
		80:  "internal_error",
		86:  "inappropriate_fallback",
		90:  "user_canceled",
		100: "no_renegotiation_RESERVED",
		109: "missing_extension",
		110: "unsupported_extension",
		111: "certificate_unobtainable_RESERVED",
		112: "unrecognized_name",
		113: "bad_certificate_status_response",
		114: "bad_certificate_hash_value_RESERVED",
		115: "unknown_psk_identity",
		116: "certificate_required",
		120: "no_application_protocol",
	}

	lastConnectionStatuses = map[uint8]string{
		0: "Connection established successfully",
		1: "Failed to connect",
	}

	lastTunnelStatuses = map[uint8]string{
		0: "Session opened and closed successfully",
		1: "Session failed due to an error",
	}
)

func getConnectionStateString(state uint8) string {
	if val, ok := connectionStates[state]; ok {
		return val
	}

	return unknownValue
}

func getConnectionTriggerString(trigger uint8) string {
	if val, ok := connectionTriggers[trigger]; ok {
		return val
	}

	return unknownValue
}

func getInterfaceTypeString(iface uint8) string {
	if val, ok := interfaceTypes[iface]; ok {
		return val
	}

	return unknownValue
}

func getDhcpModeString(mode uint8) string {
	if val, ok := dhcpModes[mode]; ok {
		return val
	}

	return unknownValue
}

func getAuthenticationMethodString(method uint8) string {
	if val, ok := authMethods[method]; ok {
		return val
	}

	return unknownValue
}

func getIPv6AddressTypeString(addrType uint8) string {
	if val, ok := ipv6AddressTypes[addrType]; ok {
		return val
	}

	return unknownValue
}

func getIPv6AddressStateString(state uint8) string {
	if val, ok := ipv6AddressStates[state]; ok {
		return val
	}

	return unknownValue
}

func getConnectionStatusString(status uint32) string {
	if val, ok := connectionStatuses[status]; ok {
		return val
	}

	return unknownValue
}

func getTcpFailureCodeString(code uint32) string {
	if val, ok := tcpFailureCodes[code]; ok {
		return val
	}

	return unknownValue
}

func getAPFDisconnectReasonString(reason uint8) string {
	if val, ok := apfDisconnectReasons[reason]; ok {
		return val
	}

	return unknownValue
}

func getClosureReasonString(reason uint8) string {
	if val, ok := closureReasons[reason]; ok {
		return val
	}

	return unknownValue
}

func getHostControlString(control uint8) string {
	if val, ok := hostControls[control]; ok {
		return val
	}

	return unknownValue
}

func getClosedByString(closedBy uint8) string {
	if val, ok := closedByEntities[closedBy]; ok {
		return val
	}

	return unknownValue
}

func getLinkStatusString(status uint8) string {
	if val, ok := linkStatuses[status]; ok {
		return val
	}

	return unknownValue
}

func getTlsFailureCodeString(code int32) string {
	if val, ok := tlsFailureCodes[code]; ok {
		return val
	}

	return fmt.Sprintf("unknown_alert_%d", code)
}

func getLastConnectionStatusString(status uint8) string {
	if val, ok := lastConnectionStatuses[status]; ok {
		return val
	}

	return unknownValue
}

func getLastTunnelStatusString(status uint8) string {
	if val, ok := lastTunnelStatuses[status]; ok {
		return val
	}

	return unknownValue
}
