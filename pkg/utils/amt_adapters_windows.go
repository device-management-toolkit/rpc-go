//go:build windows

package utils

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"strings"
)

const (
	netConnectionStatusDisconnected      = 0
	netConnectionStatusConnected         = 2
	netConnectionStatusMediaDisconnected = 7
)

func GetAMTNetworkAdapters(macs []string) ([]OSNetworkInterface, error) {
	ctx, cancel := context.WithTimeout(context.Background(), osInfoTimeout)
	defer cancel()

	executable := findTrustedAdapterPowerShellBinary()
	if executable == "" {
		return nil, fmt.Errorf("trusted PowerShell is unavailable")
	}

	script := "ConvertTo-Json -Compress -InputObject @(Get-CimInstance Win32_NetworkAdapter | Where-Object { $_.PhysicalAdapter -and $_.MACAddress } | Select-Object Name,NetConnectionID,MACAddress,NetEnabled,NetConnectionStatus)"
	output, err := runCommandOutput(ctx, executable, "-NoProfile", "-NonInteractive", "-Command", script)
	if err != nil {
		return nil, fmt.Errorf("read physical network adapters: %w", err)
	}

	var rows []struct {
		Name                string
		NetConnectionID     string
		MACAddress          string
		NetEnabled          *bool
		NetConnectionStatus *uint32
	}
	if err := json.Unmarshal(output, &rows); err != nil {
		return nil, fmt.Errorf("decode physical network adapters: %w", err)
	}

	var adapters []OSNetworkInterface
	for _, row := range rows {
		address, err := net.ParseMAC(row.MACAddress)
		if err != nil {
			continue
		}

		for _, mac := range macs {
			parsed, err := net.ParseMAC(mac)
			if err != nil || !strings.EqualFold(parsed.String(), address.String()) {
				continue
			}

			state := windowsAdapterLinkStatus(row.NetEnabled, row.NetConnectionStatus)

			adapters = append(adapters, OSNetworkInterface{
				Name: row.NetConnectionID, Description: row.Name,
				MACAddress: address.String(), LinkStatus: state,
			})
			break
		}
	}

	return adapters, nil
}

func windowsAdapterLinkStatus(netEnabled *bool, connectionStatus *uint32) string {
	if netEnabled != nil && !*netEnabled {
		return "disabled"
	}

	if connectionStatus == nil {
		return "unknown"
	}

	switch *connectionStatus {
	case netConnectionStatusConnected:
		return adapterLinkStatusUp
	case netConnectionStatusDisconnected, netConnectionStatusMediaDisconnected:
		return adapterLinkStatusDown
	default:
		return "unknown"
	}
}
