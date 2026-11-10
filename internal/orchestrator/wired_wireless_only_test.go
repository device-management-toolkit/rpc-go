/*********************************************************************
 * Copyright (c) Intel Corporation 2025
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/

package orchestrator

import (
	"errors"
	"slices"
	"testing"

	"github.com/device-management-toolkit/go-wsman-messages/v2/pkg/config"
	"github.com/device-management-toolkit/go-wsman-messages/v2/pkg/wsman/amt/ethernetport"
	"github.com/device-management-toolkit/rpc-go/v2/internal/commands"
	"github.com/device-management-toolkit/rpc-go/v2/internal/commands/configure"
	mock "github.com/device-management-toolkit/rpc-go/v2/internal/mocks"
	"go.uber.org/mock/gomock"
)

// wiredBridgeExecutor stands in for the rpc subprocess. "configure wired" runs
// the real WiredCmd against a mocked AMT; every other step is only recorded.
type wiredBridgeExecutor struct {
	wired *configure.WiredCmd
	steps []string
}

func (e *wiredBridgeExecutor) Execute(args []string, _ map[string]string) error {
	if i := slices.Index(args, commandConfigure); i >= 0 && i+1 < len(args) {
		e.steps = append(e.steps, args[i+1])

		if args[i+1] == "wired" {
			// The subprocess would exit non-zero on error; the orchestrator sees an error.
			return e.wired.Run(&commands.Context{AMTPassword: "test-pass"})
		}
	}

	return nil
}

// LAN-less device: AMT enumerates only the wireless port. The wired step must be
// skipped and the orchestrator must go on to WiFi sync and the wireless profiles.
func TestProfileOrchestrator_WirelessOnlyDevice_ContinuesToWireless(t *testing.T) {
	ctrl := gomock.NewController(t)
	wsman := mock.NewMockWSMANer(ctrl)
	wsman.EXPECT().GetEthernetSettings().Return([]ethernetport.SettingsResponse{
		{InstanceID: "Intel(r) AMT Ethernet Port Settings 1", MACAddress: "e0-d0-45-c2-fd-fd", PhysicalConnectionType: ethernetport.PhysicalConnectionWirelessLAN},
	}, nil)
	// Real firmware rejects a wired write to the wireless port.
	wsman.EXPECT().PutEthernetSettings(gomock.Any(), gomock.Any()).AnyTimes().
		Return(ethernetport.Response{}, errors.New("Error [SubCode: e:UnsupportedFeature] Message: The specified feature is not supported."))

	dhcp := true
	exec := &wiredBridgeExecutor{wired: &configure.WiredCmd{
		ConfigureBaseCmd: configure.ConfigureBaseCmd{AMTBaseCmd: commands.AMTBaseCmd{WSMan: wsman}},
		DHCPEnabled:      &dhcp,
	}}

	cfg := config.Configuration{}
	cfg.Configuration.Network.Wired.DHCPEnabled = true
	cfg.Configuration.Network.Wireless.WiFiSyncEnabled = true
	cfg.Configuration.Network.Wireless.Profiles = []config.WirelessProfile{{
		ProfileName: "home", SSID: "home-ssid", Priority: 1, Password: "psk-pass",
		AuthenticationMethod: "WPA2PSK", EncryptionMethod: "CCMP",
	}}

	po := NewProfileOrchestrator(cfg, "amt-pwd", "", false)
	po.executor = exec

	// Same sequence as the orchestrator's steps 4-6.
	if err := po.executeWiredNetworkConfiguration(); err != nil {
		t.Fatalf("wired step must not abort the profile on a wireless-only device: %v", err)
	}

	if err := po.executeEnableWiFi(); err != nil {
		t.Fatalf("wifisync: %v", err)
	}

	if err := po.executeWirelessConfigurations(); err != nil {
		t.Fatalf("wireless: %v", err)
	}

	// wired, wifisync, wireless --purge, wireless (profile "home")
	want := []string{"wired", "wifisync", "wireless", "wireless"}
	if !slices.Equal(exec.steps, want) {
		t.Fatalf("steps = %v, want %v", exec.steps, want)
	}
}
