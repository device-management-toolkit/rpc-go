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
