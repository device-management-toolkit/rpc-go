/*********************************************************************
 * Copyright (c) Intel Corporation 2025
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/

package configure

import (
	"errors"
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

	Address          string `help:"Proxy host or IP (IPv4/IPv6/FQDN)" name:"address"`
	Port             int    `help:"Proxy TCP port" default:"8080" name:"port"`
	NetworkDnsSuffix string `help:"Network DNS suffix (domain) used for the access point" name:"networkdnssuffix"`
}

// Validate implements Kong's Validate interface for proxy configuration
func (cmd *ProxyCmd) Validate() error {
	// Base validation (password etc.)
	if err := cmd.ConfigureBaseCmd.Validate(); err != nil {
		return err
	}

	if cmd.Address == "" {
		return fmt.Errorf("address is required")
	}

	if cmd.Port <= 0 || cmd.Port > 65535 {
		return fmt.Errorf("port must be between 1 and 65535")
	}

	return nil
}

// Run executes the proxy configuration command
func (cmd *ProxyCmd) Run(ctx *commands.Context) error {
	log.Info("Configuring HTTP proxy access point...")

	// Device must be activated
	if cmd.GetControlMode() == 0 {
		log.Error(ErrDeviceNotActivated)

		return errors.New(ErrDeviceNotActivated)
	}

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
		// ok
	case ipshttp.PTStatusDuplicate:
		log.Warn("Proxy access point already exists (duplicate)")
	default:
		log.Warnf("AddProxyAccessPoint returned code %d (%s)", resp.Body.AddProxyAccessPointResponse.ReturnValue, ipshttp.GetReturnValueString(resp.Body.AddProxyAccessPointResponse.ReturnValue))
	}

	log.Info("HTTP proxy access point configured successfully")

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
