//go:build !windows

/*********************************************************************
 * Copyright (c) Intel Corporation 2026
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/

package amt

import "testing"

func TestDNSSuffixFromFQDN(t *testing.T) {
	tests := []struct {
		name string
		fqdn string
		want string
	}{
		{name: "fully qualified", fqdn: "host.example.com", want: "example.com"},
		{name: "trailing dot", fqdn: "host.example.com.", want: "example.com"},
		{name: "bare hostname", fqdn: "host", want: ""},
		{name: "empty", fqdn: "", want: ""},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := dnsSuffixFromFQDN(test.fqdn); got != test.want {
				t.Fatalf("dnsSuffixFromFQDN(%q) = %q, want %q", test.fqdn, got, test.want)
			}
		})
	}
}
