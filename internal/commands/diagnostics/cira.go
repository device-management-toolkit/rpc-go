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
	"time"

	"github.com/device-management-toolkit/rpc-go/v2/internal/commands"
	"github.com/device-management-toolkit/rpc-go/v2/pkg/pthi"
)

const (
	unknownValue = "Unknown"
	zeroIP       = "0.0.0.0"
)

type field struct {
	label string
	value string
}

// CIRACmd dumps CIRA-related firmware diagnostics.
type CIRACmd struct {
	DiagnosticsBaseCmd

	Output string `help:"Output file path for the CIRA log text data" short:"o"`
}

// Run executes the CIRA diagnostics command.
func (cmd *CIRACmd) Run(ctx *commands.Context) error {
	result, err := ctx.AMTCommand.GetCiraLog()
	if err != nil {
		return err
	}

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

	// Create output file
	file, err := os.Create(cmd.Output)
	if err != nil {
		return fmt.Errorf("failed to create output file: %w", err)
	}
	defer file.Close()

	// Write CIRA log data to file
	outputCiraLogText(file, result)

	fmt.Printf("CIRA Log successfully retrieved\n")
	fmt.Printf("Output file: %s\n", cmd.Output)

	return nil
}

func outputCiraLogText(w io.Writer, result pthi.GetCiraLogResponse) {
	fmt.Fprintf(w, "Status = %d (%s)\n", result.Header.Status, result.Header.Status.String())
	fmt.Fprintf(w, "Version = %d\n", result.Version)
	fmt.Fprintln(w, "CiraStatusSummary:")

	tunnelStatus := "Closed"
	if result.CiraStatusSummary.IsTunnelOpened == 1 {
		tunnelStatus = "Opened"
	}

	fields := []field{
		{"IsTunnelOpened", fmt.Sprintf("%d (%s)", result.CiraStatusSummary.IsTunnelOpened, tunnelStatus)},
		{"CurrentConnectionState",
			fmt.Sprintf("%d (%s)",
				result.CiraStatusSummary.CurrentConnectionState,
				getConnectionStateString(result.CiraStatusSummary.CurrentConnectionState))},
		{"LastKeepAlive(The time in which the last keepalive message was sent, 0 if not currently connected)",
			fmt.Sprintf("%d(%s)",
				result.CiraStatusSummary.LastKeepAlive,
				formatTimestamp(result.CiraStatusSummary.LastKeepAlive))},
		{"KeepAliveInterval(AMT's keepalive interval in seconds, valid only if currently connected)",
			fmt.Sprint(result.CiraStatusSummary.KeepAliveInterval)},
		{"LastConnectionStatus",
			fmt.Sprintf("%d (%s)", result.CiraStatusSummary.LastConnectionStatus, getLastConnectionStatusString(result.CiraStatusSummary.LastConnectionStatus))},
		{"LastConnectionTimestamp",
			fmt.Sprintf("%d (%s)",
				result.CiraStatusSummary.LastConnectionTimestamp,
				formatTimestamp(result.CiraStatusSummary.LastConnectionTimestamp))},
		{"LastTunnelStatus",
			fmt.Sprintf("%d (%s)", result.CiraStatusSummary.LastTunnelStatus, getLastTunnelStatusString(result.CiraStatusSummary.LastTunnelStatus))},
		{"LastTunnelOpenedTimestamp",
			fmt.Sprintf("%d (%s)",
				result.CiraStatusSummary.LastTunnelOpenedTimestamp,
				formatTimestamp(result.CiraStatusSummary.LastTunnelOpenedTimestamp))},
		{"LastTunnelClosedTimestamp",
			fmt.Sprintf("%d (%s)",
				result.CiraStatusSummary.LastTunnelClosedTimestamp,
				formatTimestamp(result.CiraStatusSummary.LastTunnelClosedTimestamp))},
	}

	for _, f := range fields {
		fmt.Fprintf(w, "\t%s = %s\n", f.label, f.value)
	}

	fmt.Fprintln(w, "LastFailedTunnelLogEntry:")
	printTunnelLogEntry(w, result.LastFailedTunnelLogEntry)

	fmt.Fprintln(w, "FailedConnectionLogEntry:")
	printFailedConnectionLogEntry(w, result.FailedConnectionLogEntry)
}

func printTunnelLogEntry(w io.Writer, entry pthi.CIRATunnelLogEntry) {
	fields := []field{
		{"Valid", fmt.Sprint(entry.Valid)},
		{"OpenTimestamp", fmt.Sprintf("%d (%s)", entry.OpenTimestamp, formatTimestamp(entry.OpenTimestamp))},
		{"RemoteAccessConnectionTrigger", fmt.Sprintf("%d (%s)", entry.RemoteAccessConnectionTrigger,
			getConnectionTriggerString(entry.RemoteAccessConnectionTrigger))},
		{"MpsHostname", ansiToString(entry.MpsHostname)},
		{"ProxyUsed(Indicates whether CIRA connection is over proxy)", fmt.Sprint(entry.ProxyUsed)},
		{"ProxyName", ansiToString(entry.ProxyName)},
		{"AuthenticationMethod", fmt.Sprintf("%d (%s)", entry.AuthenticationMethod, getAuthenticationMethodString(entry.AuthenticationMethod))},
		{"ConnectedInterface", fmt.Sprintf("%d (%s)", entry.ConnectedInterface, getInterfaceTypeString(entry.ConnectedInterface))},
		{"LastKeepAlive", fmt.Sprintf("%d (%s)", entry.LastKeepAlive, formatTimestamp(entry.LastKeepAlive))},
		{"KeepAliveInterval", fmt.Sprint(entry.KeepAliveInterval)},
	}

	for _, f := range fields {
		fmt.Fprintf(w, "\t%s = %s\n", f.label, f.value)
	}

	fmt.Fprintln(w, "\tTunnelClosureInfo:")
	printTunnelClosureInfo(w, entry.TunnelClosureInfo)
}

func printFailedConnectionLogEntry(w io.Writer, entry pthi.CIRAFailedConnectionLogEntry) {
	fields := []field{
		{"Valid", fmt.Sprint(entry.Valid)},
		{"OpenTimestamp", fmt.Sprintf("%d (%s)", entry.OpenTimestamp, formatTimestamp(entry.OpenTimestamp))},
		{"RemoteAccessConnectionTrigger", fmt.Sprintf("%d (%s)", entry.RemoteAccessConnectionTrigger,
			getConnectionTriggerString(entry.RemoteAccessConnectionTrigger))},
		{"MpsHostname", ansiToString(entry.MpsHostname)},
		{"AuthenticationMethod", fmt.Sprintf("%d (%s)", entry.AuthenticationMethod, getAuthenticationMethodString(entry.AuthenticationMethod))},
	}

	for _, f := range fields {
		fmt.Fprintf(w, "\t%s = %s\n", f.label, f.value)
	}

	fmt.Fprintln(w, "\tInterfaceData:")

	// InterfaceData is a fixed-size array of 2 items: [0]=Lan, [1]=Wireless
	interfaceNames := []string{"Lan Item:", "Wireless Item:"}
	for i := 0; i < 2; i++ {
		fmt.Fprintf(w, "\t\t%s\n", interfaceNames[i])
		printInterfaceData(w, entry.InterfaceData[i])
	}

	fmt.Fprintln(w, "\tWirelessAdditionalData:")
	// Find null terminator in ProfileName byte array
	profileName := ""

	for i, b := range entry.WirelessAdditionalData.ProfileName {
		if b == 0 {
			profileName = string(entry.WirelessAdditionalData.ProfileName[:i])

			break
		}
	}

	fmt.Fprintf(w, "\t\tProfileName = %s\n", profileName)
	fmt.Fprintf(w, "\t\tHostControl = %d (%s)\n", entry.WirelessAdditionalData.HostControl, getHostControlString(entry.WirelessAdditionalData.HostControl))

	fmt.Fprintln(w, "\tWiredAdditionalData:")
	fmt.Fprintf(w, "\t\t802.1xAuthenticationResult = %d\n", entry.WiredAdditionalData.AuthResult802_1x)
	fmt.Fprintf(w, "\t\t802.1xAuthenticationSubResult = %d\n", entry.WiredAdditionalData.AuthSubResult802_1x)
	fmt.Fprintf(w, "\t\tWiredMediaType = %d\n", entry.WiredAdditionalData.WiredMediaType)
	fmt.Fprintf(w, "\t\tDiscreteLanStatus = %d\n", entry.WiredAdditionalData.DiscreteLanStatus)

	fmt.Fprintf(w, "\tConnectedInterface = %d (%s)\n", entry.ConnectedInterface, getInterfaceTypeString(entry.ConnectedInterface))

	fmt.Fprintln(w, "\tConnectionDetails:")

	// ConnectionDetails is a fixed-size array of 2 items: [0]=Lan, [1]=Wireless
	connectionNames := []string{"Lan Item:", "Wireless Item:"}
	for i := 0; i < 2; i++ {
		fmt.Fprintf(w, "\t\t%s\n", connectionNames[i])
		printConnectionDetail(w, entry.ConnectionDetails[i])
	}

	fmt.Fprintln(w, "\tTunnelEstablishmentFailure:")
	printTunnelClosureInfo(w, entry.TunnelEstablishmentFailure)
}

func printInterfaceData(w io.Writer, data pthi.InterfaceData) {
	fields := []field{
		{"\t\t\tInterfacePresent", fmt.Sprint(data.InterfacePresent)},
		{"			LinkStatus", fmt.Sprintf("%d (%s)", data.LinkStatus, getLinkStatusString(data.LinkStatus))},
	}

	for _, f := range fields {
		fmt.Fprintf(w, "\t%s = %s\n", f.label, f.value)
	}

	fmt.Fprintln(w, "\t\t\tIPParameters:")

	ipFields := []field{
		{"\t\t\t\tDhcpMode", fmt.Sprintf("%d (%s)", data.IPParameters.DhcpMode, getDhcpModeString(data.IPParameters.DhcpMode))},
		{"\t\t\t\tIpAddress", formatIPv4(data.IPParameters.IpAddress)},
		{"\t\t\t\tDefaultGatewayAddress", formatIPv4(data.IPParameters.DefaultGatewayAddress)},
		{"\t\t\t\tPrimaryDnsAddress", formatIPv4(data.IPParameters.PrimaryDnsAddress)},
		{"\t\t\t\tSecondaryDnsAddress", formatIPv4(data.IPParameters.SecondaryDnsAddress)},
		{"\t\t\t\tDomainName", ansiToString(data.IPParameters.DomainName)},
	}

	for _, f := range ipFields {
		fmt.Fprintf(w, "\t%s = %s\n", f.label, f.value)
	}

	// Always print IPv6 fields - they are physically present in structure, just zero when disabled
	fmt.Fprintln(w, "\t\t\t\tIPv6DefaultRouter:")
	fmt.Fprintf(w, "\t\t\t\t\tAddress = %s\n", formatIPv6(data.IPParameters.IPv6DefaultRouter))
	fmt.Fprintln(w, "\t\t\t\tPrimaryDNS:")
	fmt.Fprintf(w, "\t\t\t\t\tAddress = %s\n", formatIPv6(data.IPParameters.PrimaryDNS))
	fmt.Fprintln(w, "\t\t\t\tSecondaryDNS:")
	fmt.Fprintf(w, "\t\t\t\t\tAddress = %s\n", formatIPv6(data.IPParameters.SecondaryDNS))
	fmt.Fprintln(w, "\t\t\t\tIPv6Addresses:")

	// IPv6Addresses is a fixed array of 6
	for i := 0; i < pthi.MAX_IPV6_ADDRESSES; i++ {
		printIPv6AddressEntry(w, data.IPParameters.IPv6Addresses[i])
	}
}

func printIPv6AddressEntry(w io.Writer, entry pthi.IPv6AddressEntry) {
	fmt.Fprintf(w, "\t\t\t\t\tAddress = %s\n", formatIPv6(entry.Address))
	fmt.Fprintf(w, "\t\t\t\t\tType = %d (%s)\n", entry.Type, getIPv6AddressTypeString(entry.Type))
	fmt.Fprintf(w, "\t\t\t\t\tState = %d (%s)\n", entry.State, getIPv6AddressStateString(entry.State))
}

func printConnectionDetail(w io.Writer, detail pthi.ConnectionDetail) {
	fields := []field{
		{"\t\t\tConnectionStatus", fmt.Sprintf("%d (%s)", detail.ConnectionStatus, getConnectionStatusString(detail.ConnectionStatus))},
		{"\t\t\tProxyUsed", fmt.Sprint(detail.ProxyUsed)},
		{"\t\t\tProxyName", ansiToString(detail.ProxyName)},
		{"\t\t\tTcpFailureCode", fmt.Sprintf("%d (%s)", detail.TcpFailureCode, getTcpFailureCodeString(detail.TcpFailureCode))},
		{"\t\t\tTlsFailureCode", fmt.Sprintf("%d (%s)", detail.TlsFailureCode, getTlsFailureCodeString(detail.TlsFailureCode))},
	}

	for _, f := range fields {
		fmt.Fprintf(w, "\t%s = %s\n", f.label, f.value)
	}
}

func printTunnelClosureInfo(w io.Writer, info pthi.TunnelClosureInfo) {
	fields := []field{
		{"ClosureTimestamp", fmt.Sprintf("%d (%s)", info.ClosureTimestamp, formatTimestamp(info.ClosureTimestamp))},
		{"ClosedBy", fmt.Sprintf("%d (%s)", info.ClosedByMps, getClosedByString(info.ClosedByMps))},
		{"APF_DISCONNECT_REASON", fmt.Sprintf("%d (%s)", info.APF_DISCONNECT_REASON, getAPFDisconnectReasonString(info.APF_DISCONNECT_REASON))},
		{"ClosureReason", fmt.Sprintf("%d (%s)", info.ClosureReason, getClosureReasonString(info.ClosureReason))},
	}

	for _, f := range fields {
		fmt.Fprintf(w, "\t\t%s = %s\n", f.label, f.value)
	}
}

// Helper functions
func ansiToString(ansi pthi.AMTANSIString) string {
	// If Length field is not set or invalid, scan for null terminator
	length := ansi.Length
	if length == 0 || length > uint16(len(ansi.Buffer)) {
		// Find null terminator
		for i, b := range ansi.Buffer {
			if b == 0 {
				length = uint16(i)

				break
			}
		}

		if length == 0 {
			return ""
		}
	}

	return string(ansi.Buffer[:length])
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

	return fmt.Sprintf("%d.%d.%d.%d",
		byte(ip&0xFF),
		byte((ip>>8)&0xFF),
		byte((ip>>16)&0xFF),
		byte((ip>>24)&0xFF))
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

func getConnectionStateString(state uint8) string {
	switch state {
	case 0:
		return "Inside Enterprise"
	case 1:
		return "Inside Corporate Environment, outside Enterprise"
	case 2:
		return "Outside Enterprise"
	default:
		return unknownValue
	}
}

func getConnectionTriggerString(trigger uint8) string {
	switch trigger {
	case 0:
		return "User Initiated"
	case 1:
		return "Alert"
	case 2:
		return "Periodic"
	default:
		return unknownValue
	}
}

func getInterfaceTypeString(iface uint8) string {
	switch iface {
	case 0:
		return "INTERFACE_TYPE_WIRED"
	case 1:
		return "INTERFACE_TYPE_WIRELESS"
	case 2:
		return "INTERFACE_TYPE_NONE"
	default:
		return unknownValue
	}
}

func getDhcpModeString(mode uint8) string {
	switch mode {
	case 0:
		return "Disabled"
	case 1:
		return "Reserved"
	case 2:
		return "Enabled"
	default:
		return unknownValue
	}
}

func getAuthenticationMethodString(method uint8) string {
	switch method {
	case 1:
		return "MutualTLS"
	case 2:
		return "Username and password"
	default:
		return unknownValue
	}
}

func getIPv6AddressTypeString(addrType uint8) string {
	switch addrType {
	case 0:
		return "CFG_Ipv6_ADDR_TYPE_LINK_LOCAL"
	case 1:
		return "CFG_Ipv6_ADDR_TYPE_GLOBAL"
	case 2:
		return "CFG_Ipv6_ADDR_TYPE_STATELESS"
	case 3:
		return "CFG_Ipv6_ADDR_TYPE_STATEFUL"
	default:
		return unknownValue
	}
}

func getIPv6AddressStateString(state uint8) string {
	switch state {
	case 0:
		return "CFG_Ipv6_ADDR_STATE_TENTATIVE"
	case 1:
		return "CFG_Ipv6_ADDR_STATE_PREFERRED"
	case 2:
		return "CFG_Ipv6_ADDR_STATE_DEPRECATED"
	default:
		return unknownValue
	}
}

func getConnectionStatusString(status uint32) string {
	switch status {
	case 0:
		return "CIRA_LOG_CONNECTION_STATUS_NA"
	case 1:
		return "CIRA_LOG_CONNECTION_STATUS_INTERNAL_ERROR"
	case 2:
		return "CIRA_LOG_CONNECTION_STATUS_ERROR_DNS"
	case 3:
		return "CIRA_LOG_CONNECTION_STATUS_ERROR_TCP"
	case 4:
		return "CIRA_LOG_CONNECTION_STATUS_ERROR_TLS"
	case 5:
		return "CIRA_LOG_CONNECTION_STATUS_SUCCESS"
	default:
		return unknownValue
	}
}

func getTcpFailureCodeString(code uint32) string {
	switch code {
	case 0:
		return "CIRA_LOGGER_TCP_ERR_SUCCESS"
	case 1:
		return "CIRA_LOGGER_TCP_ERR_GENERAL_FAILURE"
	case 2:
		return "CIRA_LOGGER_TCP_ERR_TIMED_OUT"
	case 3:
		return "CIRA_LOGGER_TCP_ERR_CONNECTION_RESET"
	case 4:
		return "CIRA_LOGGER_TCP_ERR_DESTINATION_UNREACHABLE"
	default:
		return unknownValue
	}
}

func getAPFDisconnectReasonString(reason uint8) string {
	reasons := map[uint8]string{
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

	if str, ok := reasons[reason]; ok {
		return str
	}

	return unknownValue
}

func getClosureReasonString(reason uint8) string {
	switch reason {
	case 0:
		return "AMT_CLOSE_REASON_USER_INITIATE_REQUEST"
	case 1:
		return "AMT_CLOSE_REASON_TUNNEL_TIMER_EXPIRED"
	case 2:
		return "AMT_CLOSE_REASON_INTERNAL_ERROR"
	case 3:
		return "AMT_CLOSE_REASON_KEEP_ALIVE_EXPIRED"
	case 4:
		return "AMT_CLOSE_REASON_TCP_SOCKET_ERROR"
	default:
		return unknownValue
	}
}

func getHostControlString(control uint8) string {
	switch control {
	case 0:
		return "AMT"
	case 1:
		return "Host"
	default:
		return unknownValue
	}
}

func getClosedByString(closedBy uint8) string {
	switch closedBy {
	case 0:
		return "AMT"
	case 1:
		return "MPS"
	default:
		return unknownValue
	}
}

func getLinkStatusString(status uint8) string {
	switch status {
	case 0:
		return "Down"
	case 1:
		return "Up"
	default:
		return unknownValue
	}
}

func getTlsFailureCodeString(code int32) string {
	// TLS alert descriptions
	switch code {
	case 0:
		return "close_notify"
	case 10:
		return "unexpected_message"
	case 20:
		return "bad_record_mac"
	case 21:
		return "decryption_failed_RESERVED"
	case 22:
		return "record_overflow"
	case 30:
		return "decompression_failure_RESERVED"
	case 40:
		return "handshake_failure"
	case 41:
		return "no_certificate_RESERVED"
	case 42:
		return "bad_certificate"
	case 43:
		return "unsupported_certificate"
	case 44:
		return "certificate_revoked"
	case 45:
		return "certificate_expired"
	case 46:
		return "certificate_unknown"
	case 47:
		return "illegal_parameter"
	case 48:
		return "unknown_ca"
	case 49:
		return "access_denied"
	case 50:
		return "decode_error"
	case 51:
		return "decrypt_error"
	case 60:
		return "export_restriction_RESERVED"
	case 70:
		return "protocol_version"
	case 71:
		return "insufficient_security"
	case 80:
		return "internal_error"
	case 86:
		return "inappropriate_fallback"
	case 90:
		return "user_canceled"
	case 100:
		return "no_renegotiation_RESERVED"
	case 109:
		return "missing_extension"
	case 110:
		return "unsupported_extension"
	case 111:
		return "certificate_unobtainable_RESERVED"
	case 112:
		return "unrecognized_name"
	case 113:
		return "bad_certificate_status_response"
	case 114:
		return "bad_certificate_hash_value_RESERVED"
	case 115:
		return "unknown_psk_identity"
	case 116:
		return "certificate_required"
	case 120:
		return "no_application_protocol"
	default:
		return fmt.Sprintf("unknown_alert_%d", code)
	}
}

func getLastConnectionStatusString(status uint8) string {
	switch status {
	case 0:
		return "Connection established successfully"
	case 1:
		return "Failed to connect"
	default:
		return unknownValue
	}
}

func getLastTunnelStatusString(status uint8) string {
	switch status {
	case 0:
		return "Session opened and closed successfully"
	case 1:
		return "Session failed due to an error"
	default:
		return unknownValue
	}
}
