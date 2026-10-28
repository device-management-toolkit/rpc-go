//go:build windows

package utils

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestWindowsAdapterLinkStatus(t *testing.T) {
	connected := uint32(netConnectionStatusConnected)
	disconnected := uint32(netConnectionStatusMediaDisconnected)
	disabled := false
	enabled := true
	tests := []struct {
		name             string
		netEnabled       *bool
		connectionStatus *uint32
		want             string
	}{
		{name: "connected", netEnabled: &enabled, connectionStatus: &connected, want: "up"},
		{name: "no carrier", netEnabled: &enabled, connectionStatus: &disconnected, want: "down"},
		{name: "administratively disabled", netEnabled: &disabled, connectionStatus: &connected, want: "disabled"},
		{name: "unknown connection status", netEnabled: &enabled, want: "unknown"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assert.Equal(t, test.want, windowsAdapterLinkStatus(test.netEnabled, test.connectionStatus))
		})
	}
}
