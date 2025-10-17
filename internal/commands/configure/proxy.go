/*********************************************************************
 * Copyright (c) Intel Corporation 2025
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/

package configure

import (
	"fmt"
	"net"
	"strings"

	ipshttp "github.com/device-management-toolkit/go-wsman-messages/v2/pkg/wsman/ips/http"
	"github.com/device-management-toolkit/rpc-go/v2/internal/commands"
	log "github.com/sirupsen/logrus"
)

// ProxyCmd configures the HTTP Proxy Access Point used by Intel AMT firmware
// for user-initiated connections (e.g., CIRA/OCR via BIOS screens).
// It maps to IPS_HTTPProxyService.AddProxyAccessPoint.
type ProxyCmd struct {
	ConfigureBaseCmd

	List             bool   `help:"List existing HTTP proxy settings" name:"list"`
	Delete           bool   `help:"Delete a proxy access point by address" name:"delete"`
	Address          string `help:"Proxy host or IP (IPv4/IPv6/FQDN)" name:"address"`
	Port             int    `help:"Proxy TCP port" name:"port" default:"80"`
	NetworkDnsSuffix string `help:"Network DNS suffix (domain) used for the access point" name:"networkdnssuffix"`
}

// Validate implements Kong's Validate interface for proxy configuration
func (cmd *ProxyCmd) Validate() error {
	// Base validation (password etc.)
	if err := cmd.ConfigureBaseCmd.Validate(); err != nil {
		return err
	}

	// Check for mutually exclusive flags
	if cmd.List && cmd.Delete {
		return fmt.Errorf("cannot use --list and --delete flags together")
	}

	// If listing, no other parameters are needed
	if cmd.List {
		return nil
	}

	// If deleting, only require address
	if cmd.Delete {
		if cmd.Address == "" {
			return fmt.Errorf("address is required when using --delete")
		}

		if len(cmd.Address) > 256 {
			return fmt.Errorf("address length must not exceed 256 characters")
		}

		return nil
	}

	// For adding a proxy, require address and network DNS suffix
	if cmd.Address == "" {
		return fmt.Errorf("address is required for adding a proxy")
	}

	if cmd.NetworkDnsSuffix == "" {
		return fmt.Errorf("network DNS suffix is required for adding a proxy")
	}

	if len(cmd.Address) > 256 {
		return fmt.Errorf("address length must not exceed 256 characters")
	}

	if len(cmd.NetworkDnsSuffix) > 192 {
		return fmt.Errorf("network DNS suffix length must not exceed 192 characters")
	}

	if cmd.Port <= 0 || cmd.Port > 65535 {
		return fmt.Errorf("port must be between 1 and 65535")
	}

	return nil
}

// Run executes the proxy configuration command
func (cmd *ProxyCmd) Run(ctx *commands.Context) error {
	// Ensure runtime initialization (password + WSMAN client)
	if err := cmd.EnsureRuntime(ctx); err != nil {
		return err
	}
	// Device must be activated
	if cmd.GetControlMode() == 0 {
		log.Error(ErrDeviceNotActivated)

		return ErrDeviceNotActivated
	}

	// Handle listing proxy settings
	if cmd.List {
		log.Info("Retrieving HTTP proxy access points...")

		accessPoints, err := cmd.WSMan.GetHTTPProxyAccessPoints()
		if err != nil {
			return fmt.Errorf("failed to retrieve HTTP proxy access points: %w", err)
		}

		// Display the proxy access points
		if len(accessPoints) == 0 {
			log.Info("No HTTP proxy access points configured")
		} else {
			log.Info("HTTP Proxy Access Points:")

			for i, ap := range accessPoints {
				log.Infof("  [%d] Address: %s", i+1, ap.AccessInfo)
				log.Infof("      Port: %d", ap.Port)
				log.Infof("      DNS Suffix: %s", ap.NetworkDnsSuffix)

				// Convert InfoFormat to readable string
				formatStr := "Unknown"

				switch ap.InfoFormat {
				case 3:
					formatStr = "IPv4"
				case 4:
					formatStr = "IPv6"
				case 201:
					formatStr = "FQDN"
				}

				log.Infof("      Type: %s", formatStr)

				if ap.Name != "" {
					log.Infof("      Name: %s", ap.Name)
				}
			}
		}

		return nil
	}

	// Handle deleting proxy access point
	if cmd.Delete {
		log.Infof("Deleting HTTP proxy access point for address: %s", cmd.Address)

		// First, get all access points to find the one that matches the address
		accessPoints, err := cmd.WSMan.GetHTTPProxyAccessPoints()
		if err != nil {
			return fmt.Errorf("failed to retrieve HTTP proxy access points: %w", err)
		}

		// Find the matching access point
		var matchingAccessPoint *ipshttp.HTTPProxyAccessPointItem

		for _, ap := range accessPoints {
			if ap.AccessInfo == cmd.Address && (cmd.Port == 80 || ap.Port == cmd.Port) {
				matchingAccessPoint = &ap

				break
			}
		}

		if matchingAccessPoint == nil {
			return fmt.Errorf("no HTTP proxy access point found with address: %s", cmd.Address)
		}

		log.Infof("Found matching access point: %s (Port: %d, DNS Suffix: %s)",
			matchingAccessPoint.AccessInfo, matchingAccessPoint.Port, matchingAccessPoint.NetworkDnsSuffix)

		// Delete the proxy access point using the Name field
		_, err = cmd.WSMan.DeleteHTTPProxyAccessPoint(matchingAccessPoint.Name)
		if err != nil {
			return fmt.Errorf("failed to delete HTTP proxy access point: %w", err)
		}

		log.Infof("HTTP proxy access point for %s deleted successfully", cmd.Address)

		return nil
	}

	// Handle adding proxy access point
	log.Info("Configuring HTTP proxy access point...")

	// Determine InfoFormat from address
	infoFormat := inferInfoFormat(cmd.Address)

	// Call WSMAN implementation
	resp, err := cmd.WSMan.AddHTTPProxyAccessPoint(cmd.Address, int(infoFormat), cmd.Port, cmd.NetworkDnsSuffix)
	if err != nil {
		return fmt.Errorf("failed to add HTTP proxy access point: %w", err)
	}

	// Map known return codes for better logs
	switch resp.Body.AddProxyAccessPointResponse.ReturnValue {
	case ipshttp.PTStatusSuccess:
		log.Info("HTTP proxy access point configured successfully")
	case ipshttp.PTStatusDuplicate:
		log.Error("Proxy access point already exists (duplicate)")
	default:
		log.Errorf("AddProxyAccessPoint returned code %d (%s)", resp.Body.AddProxyAccessPointResponse.ReturnValue, ipshttp.GetReturnValueString(resp.Body.AddProxyAccessPointResponse.ReturnValue))
	}

	return nil
}

// inferInfoFormat determines IPS HTTP InfoFormat from the given address
func inferInfoFormat(address string) ipshttp.InfoFormat {
	// IPv6 addresses can be in bracket form or raw
	// Try IP parse first
	ip := net.ParseIP(strings.Trim(address, "[]"))
	if ip != nil {
		if ip.To4() != nil {
			return ipshttp.InfoFormatIPv4
		}

		return ipshttp.InfoFormatIPv6
	}

	// Otherwise, treat as FQDN
	return ipshttp.InfoFormatFQDN
}
