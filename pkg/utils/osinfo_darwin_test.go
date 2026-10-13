/*********************************************************************
 * Copyright (c) Intel Corporation 2026
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/

package utils

import (
	"context"
	"errors"
	"testing"
)

const hardwarePortsOutput = `
Hardware Port: Ethernet Adapter (en4)
Device: en4
Ethernet Address: 46:b3:ee:00:00:01

Hardware Port: Wi-Fi
Device: en0
Ethernet Address: ee:75:db:00:00:02

Hardware Port: Thunderbolt 1
Device: en1
Ethernet Address: 36:f4:49:00:00:03

VLAN Configurations
===================
`

func TestIsWirelessInterface(t *testing.T) {
	original := runNetworksetup

	t.Cleanup(func() { runNetworksetup = original })

	runNetworksetup = func(_ context.Context, _ ...string) ([]byte, error) {
		return []byte(hardwarePortsOutput), nil
	}

	tests := []struct {
		name string
		want bool
	}{
		{name: "en0", want: true},
		{name: "en4", want: false},
		{name: "en1", want: false},
		{name: "en9", want: false},
		{name: "wlan0", want: true},
	}

	for _, tt := range tests {
		tt := tt

		t.Run(tt.name, func(t *testing.T) {
			if got := isWirelessInterface(tt.name); got != tt.want {
				t.Fatalf("isWirelessInterface(%q) = %v, want %v", tt.name, got, tt.want)
			}
		})
	}
}

func TestIsWirelessInterface_NetworksetupFailure(t *testing.T) {
	original := runNetworksetup

	t.Cleanup(func() { runNetworksetup = original })

	runNetworksetup = func(_ context.Context, _ ...string) ([]byte, error) {
		return nil, errors.New("networksetup not found")
	}

	if isWirelessInterface("en0") {
		t.Fatal("isWirelessInterface(\"en0\") = true, want false when hardware ports are unavailable")
	}

	if !isWirelessInterface("wlan0") {
		t.Fatal("isWirelessInterface(\"wlan0\") = false, want true from the name alone")
	}
}
