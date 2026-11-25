/*********************************************************************
 * Copyright (c) Intel Corporation 2025
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/

package configure

import (
	"fmt"
	"os"

	"github.com/device-management-toolkit/go-wsman-messages/v2/pkg/wsman/amt/general"
	"github.com/device-management-toolkit/rpc-go/v2/internal/commands"
	"github.com/device-management-toolkit/rpc-go/v2/pkg/utils"
	log "github.com/sirupsen/logrus"
)

// SyncHostnameCmd synchronizes host OS hostname to AMT general settings
type SyncHostnameCmd struct {
	ConfigureBaseCmd
}

// Run executes the hostname sync command
func (cmd *SyncHostnameCmd) Run(ctx *commands.Context) error {
	// Ensure runtime initialization (password + WSMAN client)
	if err := cmd.EnsureRuntime(ctx); err != nil {
		return err
	}
	// Require activated device
	if cmd.GetControlMode() == 0 {
		log.Error(ErrDeviceNotActivated)

		return ErrDeviceNotActivated
	}

	// Retrieve OS hostname and DNS suffix via AMT helpers
	dnsSuffix, err := ctx.AMTCommand.GetOSDNSSuffix()
	if err != nil {
		log.Error(err)
	}

	hostname, err := os.Hostname()
	if err != nil || hostname == "" {
		log.Error("OS hostname is not available")

		return utils.OSNetworkInterfacesLookupFailed
	}

	// AMT rejects a Put that omits the settings it requires, so start from the current values.
	current, err := cmd.WSMan.GetGeneralSettings()
	if err != nil {
		return fmt.Errorf("failed to get general settings: %w", err)
	}

	req := generalSettingsRequest(current.Body.GetResponse)
	req.HostName = hostname

	if dnsSuffix != "" {
		req.DomainName = dnsSuffix
	}

	if _, err := cmd.WSMan.PutGeneralSettings(req); err != nil {
		return fmt.Errorf("failed to update general settings: %w", err)
	}

	log.Infof("Synchronized AMT hostname to '%s' with DNS suffix '%s'", hostname, dnsSuffix)

	return nil
}

// generalSettingsRequest copies the writable fields of the current settings into a Put request.
func generalSettingsRequest(g general.GeneralSettingsResponse) general.GeneralSettingsRequest {
	return general.GeneralSettingsRequest{
		ElementName:                   g.ElementName,
		InstanceID:                    g.InstanceID,
		IdleWakeTimeout:               g.IdleWakeTimeout,
		HostName:                      g.HostName,
		DomainName:                    g.DomainName,
		PingResponseEnabled:           g.PingResponseEnabled,
		WsmanOnlyMode:                 g.WsmanOnlyMode,
		PreferredAddressFamily:        g.PreferredAddressFamily,
		DHCPv6ConfigurationTimeout:    g.DHCPv6ConfigurationTimeout,
		DDNSUpdateEnabled:             g.DDNSUpdateEnabled,
		DDNSUpdateByDHCPServerEnabled: g.DDNSUpdateByDHCPServerEnabled,
		SharedFQDN:                    g.SharedFQDN,
		HostOSFQDN:                    g.HostOSFQDN,
		DDNSTTL:                       g.DDNSTTL,
		AMTNetworkEnabled:             g.AMTNetworkEnabled,
		RmcpPingResponseEnabled:       g.RmcpPingResponseEnabled,
		DDNSPeriodicUpdateInterval:    g.DDNSPeriodicUpdateInterval,
		PresenceNotificationInterval:  g.PresenceNotificationInterval,
		ThunderboltDockEnabled:        g.ThunderboltDockEnabled,
		DHCPSyncRequiresHostname:      int(g.DHCPSyncRequiresHostname),
	}
}
