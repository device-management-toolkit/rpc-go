/*********************************************************************
 * Copyright (c) Intel Corporation 2026
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/

package utils

import "testing"

func TestIsPhysicalEthernet(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		want bool
	}{
		{name: "eth0", want: true},
		{name: "enp100s0", want: true},
		{name: "ethernet", want: true},
		{name: "ethernet 2", want: true},
		{name: "wi-fi", want: false},
		{name: "wlan0", want: false},
	}

	for _, tt := range tests {
		tt := tt

		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if got := isPhysicalEthernet(tt.name); got != tt.want {
				t.Fatalf("isPhysicalEthernet(%q) = %v, want %v", tt.name, got, tt.want)
			}
		})
	}
}

func TestIsWirelessAdapter(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		want bool
	}{
		{name: "wlo1", want: true},
		{name: "Wi-Fi", want: true},
		{name: "Network controller: Intel Corporation Meteor Lake PCH CNVi WiFi (rev 20)", want: true},
		{name: "Ethernet", want: false},
	}

	for _, tt := range tests {
		tt := tt

		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if got := isWirelessAdapter(tt.name); got != tt.want {
				t.Fatalf("isWirelessAdapter(%q) = %v, want %v", tt.name, got, tt.want)
			}
		})
	}
}
