/*********************************************************************
 * Copyright (c) Intel Corporation 2026
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/

package configure

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSyncClock(t *testing.T) {
	err := SyncClock(BaseOptions{})
	assert.Error(t, err, "SyncClock should return an error without AMT hardware")
}

func TestSyncHostname(t *testing.T) {
	err := SyncHostname(BaseOptions{})
	assert.Error(t, err, "SyncHostname should return an error without AMT hardware")
}

func TestEnableAMT(t *testing.T) {
	err := EnableAMT(BaseOptions{})
	assert.Error(t, err, "EnableAMT should return an error without AMT hardware")
}

func TestDisableAMT(t *testing.T) {
	err := DisableAMT(BaseOptions{})
	assert.Error(t, err, "DisableAMT should return an error without AMT hardware")
}

func TestChangeAMTPassword(t *testing.T) {
	err := ChangeAMTPassword(AMTPasswordOptions{})
	assert.Error(t, err, "ChangeAMTPassword should return an error without AMT hardware")
}

func TestSetMEBx(t *testing.T) {
	err := SetMEBx(MEBxOptions{})
	assert.Error(t, err, "SetMEBx should return an error without AMT hardware")
}

func TestSetAMTFeatures(t *testing.T) {
	err := SetAMTFeatures(AMTFeaturesOptions{KVM: true})
	assert.Error(t, err, "SetAMTFeatures should return an error without AMT hardware")
}

func TestConfigureWiFiSync(t *testing.T) {
	err := ConfigureWiFiSync(WiFiSyncOptions{OSWiFiSync: true})
	assert.Error(t, err, "ConfigureWiFiSync should return an error without AMT hardware")
}

func TestConfigureWireless(t *testing.T) {
	err := ConfigureWireless(WirelessOptions{ProfileName: "test"})
	assert.Error(t, err, "ConfigureWireless should return an error without AMT hardware")
}

func TestConfigureWired(t *testing.T) {
	dhcp := true
	err := ConfigureWired(WiredOptions{DHCPEnabled: &dhcp})
	assert.Error(t, err, "ConfigureWired should return an error without AMT hardware")
}

func TestConfigureTLS(t *testing.T) {
	err := ConfigureTLS(TLSOptions{})
	assert.Error(t, err, "ConfigureTLS should return an error without AMT hardware")
}

func TestConfigureCIRA(t *testing.T) {
	err := ConfigureCIRA(CIRAOptions{MPSAddress: "https://mps.example.com"})
	assert.Error(t, err, "ConfigureCIRA should return an error without AMT hardware")
}

func TestConfigureProxy(t *testing.T) {
	err := ConfigureProxy(ProxyOptions{List: true})
	assert.Error(t, err, "ConfigureProxy should return an error without AMT hardware")
}
