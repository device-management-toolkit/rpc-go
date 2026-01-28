/*********************************************************************
 * Copyright (c) Intel Corporation 2026
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/

package commands

import (
	"encoding/json"
	"fmt"
	"net"
	"time"

	"github.com/device-management-toolkit/rpc-go/v2/pkg/pthi"
)

const (
	unknownValue = "Unknown"
)

// CiraLogCmd represents the ciralog command
type CiraLogCmd struct {
	AMTBaseCmd
}

// Run executes the ciralog command
func (cmd *CiraLogCmd) Run(ctx *Context) error {
	result, err := ctx.AMTCommand.GetCiraLog()
	if err != nil {
		return err
	}

	if ctx.JsonOutput {
		return outputCiraLogJSON(result)
	}

	return outputCiraLogText(result)
}

func outputCiraLogJSON(result pthi.GetCiraLogResponse) error {
	jsonData, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return err
	}

	fmt.Println(string(jsonData))

	return nil
}

func outputCiraLogText(result pthi.GetCiraLogResponse) error {
	fmt.Printf("Status = %d (%s)\n", result.Header.Status, result.Header.Status.String())
	fmt.Printf("Version = %d\n", result.Version)
	fmt.Println("CiraStatusSummary:")
	fmt.Printf("\tIsTunnelOpened(0-Closed, 1-Opened) = %d\n", result.CiraStatusSummary.IsTunnelOpened)
	fmt.Printf("\tCurrentConnectionState = %d (%s)\n", result.CiraStatusSummary.CurrentConnectionState,
		getConnectionStateString(result.CiraStatusSummary.CurrentConnectionState))
	fmt.Printf("\tLastKeepAlive(The time in which the last keepalive message was sent, 0 if not currently connected) = %d(%s)\n",
		result.CiraStatusSummary.LastKeepAlive, formatTimestamp(result.CiraStatusSummary.LastKeepAlive))
	fmt.Printf("\tKeepAliveInterval(AMT's keepalive interval in seconds, valid only if currently connected) = %d\n",
		result.CiraStatusSummary.KeepAliveInterval)
	fmt.Printf("\tLastConnectionStatus(MPS:0 - Connection established successfully, 1 - Failed to connect) = %d\n",
		result.CiraStatusSummary.LastConnectionStatus)
	fmt.Printf("\tLastConnectionTimestamp = %d (%s)\n", result.CiraStatusSummary.LastConnectionTimestamp,
		formatTimestamp(result.CiraStatusSummary.LastConnectionTimestamp))
	fmt.Printf("\tLastTunnelStatus(0 - Session opened and closed successfully., 1 - Session failed due to an error) = %d\n",
		result.CiraStatusSummary.LastTunnelStatus)
	fmt.Printf("\tLastTunnelOpenedTimestamp = %d (%s)\n", result.CiraStatusSummary.LastTunnelOpenedTimestamp,
		formatTimestamp(result.CiraStatusSummary.LastTunnelOpenedTimestamp))
	fmt.Printf("\tLastTunnelClosedTimestamp = %d (%s)\n", result.CiraStatusSummary.LastTunnelClosedTimestamp,
		formatTimestamp(result.CiraStatusSummary.LastTunnelClosedTimestamp))

	fmt.Println("LastFailedTunnelLogEntry:")
	printTunnelLogEntry(result.LastFailedTunnelLogEntry)

	fmt.Println("FailedConnectionLogEntry:")
	printFailedConnectionLogEntry(result.FailedConnectionLogEntry)

	return nil
}

func printTunnelLogEntry(entry pthi.CIRATunnelLogEntry) {
	fmt.Printf("\tValid = %d\n", entry.Valid)
	fmt.Printf("\tOpenTimestamp = %d (%s)\n", entry.OpenTimestamp, formatTimestamp(entry.OpenTimestamp))
	fmt.Printf("\tRemoteAccessConnectionTrigger = %d (%s)\n", entry.RemoteAccessConnectionTrigger,
		getConnectionTriggerString(entry.RemoteAccessConnectionTrigger))
	fmt.Printf("\tMpsHostname = %s\n", ansiToString(entry.MpsHostname))
	fmt.Printf("\tProxyUsed(Indicates whether CIRA connection is over proxy)= %d\n", entry.ProxyUsed)
	fmt.Printf("\tProxyName = %s\n", ansiToString(entry.ProxyName))
	fmt.Printf("\tAuthenticationMethod(MPS:1 - Mutual TLS, 2 - Username and password) = %d\n", entry.AuthenticationMethod)
	fmt.Printf("\tConnectedInterface = %d (%s)\n", entry.ConnectedInterface, getInterfaceTypeString(entry.ConnectedInterface))
	fmt.Printf("\tLastKeepAlive = %d (%s)\n", entry.LastKeepAlive, formatTimestamp(entry.LastKeepAlive))
	fmt.Printf("\tKeepAliveInterval = %d\n", entry.KeepAliveInterval)
	fmt.Println("\tTunnelClosureInfo:")
	printTunnelClosureInfo(entry.TunnelClosureInfo)
}

func printFailedConnectionLogEntry(entry pthi.CIRAFailedConnectionLogEntry) {
	fmt.Printf("\tValid = %d\n", entry.Valid)
	fmt.Printf("\tOpenTimestamp = %d (%s)\n", entry.OpenTimestamp, formatTimestamp(entry.OpenTimestamp))
	fmt.Printf("\tRemoteAccessConnectionTrigger = %d (%s)\n", entry.RemoteAccessConnectionTrigger,
		getConnectionTriggerString(entry.RemoteAccessConnectionTrigger))
	fmt.Printf("\tMpsHostname = %s\n", ansiToString(entry.MpsHostname))
	fmt.Printf("\tAuthenticationMethod(MPS:1 - Mutual TLS, 2 - Username and password) = %d\n", entry.AuthenticationMethod)
	fmt.Println("\tInterfaceData:")

	for i := uint32(0); i < entry.InterfaceDataCount && i < 2; i++ {
		fmt.Println("\t\tItem:")
		printInterfaceData(entry.InterfaceData[i])
	}

	fmt.Println("\tWirelessAdditionalData:")
	fmt.Printf("\t\tProfileName = %s\n", ansiToString(entry.WirelessAdditionalData.ProfileName))
	fmt.Printf("\t\tHostControl = %d\n", entry.WirelessAdditionalData.HostControl)

	fmt.Println("\tWiredAdditionalData:")
	fmt.Printf("\t\t802.1xAuthenticationResult = %d\n", entry.WiredAdditionalData.AuthResult802_1x)
	fmt.Printf("\t\t802.1xAuthenticationSubResult = %d\n", entry.WiredAdditionalData.AuthSubResult802_1x)
	fmt.Printf("\t\tWiredMediaType = %d\n", entry.WiredAdditionalData.WiredMediaType)
	fmt.Printf("\t\tDiscreteLanStatus = %d\n", entry.WiredAdditionalData.DiscreteLanStatus)

	fmt.Printf("\tConnectedInterface = %d (%s)\n", entry.ConnectedInterface, getInterfaceTypeString(entry.ConnectedInterface))

	fmt.Println("\tConnectionDetails:")

	for i := uint32(0); i < entry.ConnectionDetailsCount && i < 2; i++ {
		fmt.Println("\t\tItem:")
		printConnectionDetail(entry.ConnectionDetails[i])
	}

	fmt.Println("\tTunnelEstablishmentFailure:")
	printTunnelClosureInfo(entry.TunnelEstablishmentFailure)
}

func printInterfaceData(data pthi.InterfaceData) {
	fmt.Printf("\t\t\tInterfacePresent = %d\n", data.InterfacePresent)
	fmt.Printf("\t\t\tLinkStatus = %d\n", data.LinkStatus)
	fmt.Println("\t\t\tIPParameters:")
	fmt.Printf("\t\t\t\tDhcpMode = %d (%s)\n", data.IPParameters.DhcpMode, getDhcpModeString(data.IPParameters.DhcpMode))
	fmt.Printf("\t\t\t\tIpAddress = %s\n", formatIPv4(data.IPParameters.IpAddress))
	fmt.Printf("\t\t\t\tDefaultGatewayAddress = %s\n", formatIPv4(data.IPParameters.DefaultGatewayAddress))
	fmt.Printf("\t\t\t\tPrimaryDnsAddress = %s\n", formatIPv4(data.IPParameters.PrimaryDnsAddress))
	fmt.Printf("\t\t\t\tSecondaryDnsAddress = %s\n", formatIPv4(data.IPParameters.SecondaryDnsAddress))
	fmt.Printf("\t\t\t\tDomainName = %s\n", ansiToString(data.IPParameters.DomainName))
	fmt.Println("\t\t\t\tIPv6DefaultRouter:")
	fmt.Printf("\t\t\t\t\tAddress = %s\n", formatIPv6(data.IPParameters.IPv6DefaultRouter))
	fmt.Println("\t\t\t\tPrimaryDNS:")
	fmt.Printf("\t\t\t\t\tAddress = %s\n", formatIPv6(data.IPParameters.PrimaryDNS))
	fmt.Println("\t\t\t\tSecondaryDNS:")
	fmt.Printf("\t\t\t\t\tAddress = %s\n", formatIPv6(data.IPParameters.SecondaryDNS))
	fmt.Println("\t\t\t\tIPv6Addresses:")

	for i := uint32(0); i < data.IPParameters.IPv6AddressesCount && i < pthi.MAX_IPV6_ADDRESSES; i++ {
		fmt.Println("\t\t\t\t\tItem:")
		printIPv6AddressEntry(data.IPParameters.IPv6Addresses[i])
	}
}

func printIPv6AddressEntry(entry pthi.IPv6AddressEntry) {
	fmt.Println("\t\t\t\t\t\tAddress:")
	fmt.Printf("\t\t\t\t\t\t\tAddress = %s\n", formatIPv6(entry.Address))
	fmt.Printf("\t\t\t\t\t\tType = %d (%s)\n", entry.Type, getIPv6AddressTypeString(entry.Type))
	fmt.Printf("\t\t\t\t\t\tState = %d (%s)\n", entry.State, getIPv6AddressStateString(entry.State))
}

func printConnectionDetail(detail pthi.ConnectionDetail) {
	fmt.Printf("\t\t\tConnectionStatus = %d (%s)\n", detail.ConnectionStatus, getConnectionStatusString(detail.ConnectionStatus))
	fmt.Printf("\t\t\tProxyUsed = %d\n", detail.ProxyUsed)
	fmt.Printf("\t\t\tProxyName = %s\n", ansiToString(detail.ProxyName))
	fmt.Printf("\t\t\tTcpFailureCode = %d (%s)\n", detail.TcpFailureCode, getTcpFailureCodeString(detail.TcpFailureCode))
	fmt.Printf("\t\t\tTlsFailureCode = %d\n", detail.TlsFailureCode)
}

func printTunnelClosureInfo(info pthi.TunnelClosureInfo) {
	fmt.Printf("\t\tClosureTimestamp = %d\n", info.ClosureTimestamp)
	fmt.Printf("\t\tClosedByMps(0-Closed by AMT, 1-Close by MPS) = %d\n", info.ClosedByMps)
	fmt.Printf("\t\tAPF_DISCONNECT_REASON = %d  %s\n", info.APF_DISCONNECT_REASON, getAPFDisconnectReasonString(info.APF_DISCONNECT_REASON))
	fmt.Printf("\t\tClosureReason = %d (%s)\n", info.ClosureReason, getClosureReasonString(info.ClosureReason))
}

// Helper functions
func ansiToString(ansi pthi.AMTANSIString) string {
	if ansi.Length == 0 || ansi.Length > uint16(len(ansi.Buffer)) {
		return ""
	}

	return string(ansi.Buffer[:ansi.Length])
}

func formatTimestamp(ts uint32) string {
	if ts == 0 {
		return "1970-01-01 00:00:00"
	}

	t := time.Unix(int64(ts), 0)

	return t.Format("2006-01-02 15:04:05")
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

func getConnectionStatusString(status uint8) string {
	switch status {
	case 0:
		return "Success"
	case 1:
		return "Failed"
	case 2:
		return "Other"
	default:
		return unknownValue
	}
}

func getTcpFailureCodeString(code uint8) string {
	switch code {
	case 0:
		return "Other"
	case 1:
		return "Connection Refused"
	case 2:
		return "Connection Timed Out"
	case 3:
		return "Network Unreachable"
	case 4:
		return "Host Unreachable"
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
		return "AMT_CLOSE_REASON_ERROR"
	case 2:
		return "AMT_CLOSE_REASON_KEEP_ALIVE_TIMEOUT"
	case 3:
		return "AMT_CLOSE_REASON_KEEP_ALIVE_RESPONSE_TIMEOUT"
	case 4:
		return "AMT_CLOSE_REASON_TCP_SOCKET_ERROR"
	default:
		return unknownValue
	}
}
