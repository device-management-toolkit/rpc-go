//go:build !windows

package utils

import (
	"net"
	"os"
	"path/filepath"
	"strings"
)

func GetAMTNetworkAdapters(macs []string) ([]OSNetworkInterface, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}

	var adapters []OSNetworkInterface

	for _, iface := range interfaces {
		for _, mac := range macs {
			parsed, parseErr := net.ParseMAC(mac)
			if parseErr != nil || len(iface.HardwareAddr) == 0 || !strings.EqualFold(parsed.String(), iface.HardwareAddr.String()) {
				continue
			}

			state := interfaceLinkStatus(iface.Name)

			adapters = append(adapters, OSNetworkInterface{
				Name: iface.Name, Description: getAdapterDisplayName(iface.Name),
				MACAddress: iface.HardwareAddr.String(), LinkStatus: state,
			})

			break
		}
	}

	return adapters, nil
}

func interfaceLinkStatus(interfaceName string) string {
	interfacePath := filepath.Join("/sys/class/net", interfaceName)
	carrier, carrierErr := os.ReadFile(filepath.Join(interfacePath, "carrier"))
	operstate, operstateErr := os.ReadFile(filepath.Join(interfacePath, "operstate"))

	return resolveInterfaceLinkStatus(carrier, carrierErr, operstate, operstateErr)
}

func resolveInterfaceLinkStatus(carrier []byte, carrierErr error, operstate []byte, operstateErr error) string {
	if carrierErr == nil {
		if status := parseInterfaceCarrier(string(carrier)); status != "" {
			return status
		}
	}

	if operstateErr != nil {
		return "unknown"
	}

	return parseInterfaceOperstate(string(operstate))
}

func parseInterfaceCarrier(carrier string) string {
	switch strings.TrimSpace(carrier) {
	case "1":
		return adapterLinkStatusUp
	case "0":
		return adapterLinkStatusDown
	default:
		return ""
	}
}

func parseInterfaceOperstate(operstate string) string {
	switch strings.ToLower(strings.TrimSpace(operstate)) {
	case adapterLinkStatusUp:
		return adapterLinkStatusUp
	case adapterLinkStatusDown, "lowerlayerdown", "notpresent":
		return adapterLinkStatusDown
	default:
		return "unknown"
	}
}
