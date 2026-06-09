/*********************************************************************
 * Copyright (c) Intel Corporation 2026
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/

package utils

import "testing"

func TestParseMEIModuleVersionFromPath(t *testing.T) {
	tests := []struct {
		name       string
		modulePath string
		want       string
		wantOK     bool
	}{
		{
			name:       "in-tree ubuntu 24.04 module path",
			modulePath: "/lib/modules/6.17.0-35-generic/kernel/drivers/misc/mei/mei-me.ko.zst",
			want:       "6.17.0-35-generic",
			wantOK:     true,
		},
		{
			name:       "in-tree ubuntu 22.04 module path",
			modulePath: "/lib/modules/5.15.0-164-generic/kernel/drivers/misc/mei/mei-me.ko",
			want:       "5.15.0-164-generic",
			wantOK:     true,
		},
		{
			name:       "updates path gets updates suffix",
			modulePath: "/lib/modules/6.17.0-35-generic/updates/mei-me.ko",
			want:       "6.17.0-35-generic-updates",
			wantOK:     true,
		},
		{
			name:       "updates dkms path gets updates suffix",
			modulePath: "/lib/modules/6.17.0-35-generic/updates/dkms/mei-me.ko",
			want:       "6.17.0-35-generic-updates",
			wantOK:     true,
		},
		{
			name:       "extra path gets extra suffix",
			modulePath: "/lib/modules/6.17.0-35-generic/extra/mei-me.ko",
			want:       "6.17.0-35-generic-extra",
			wantOK:     true,
		},
		{
			name:       "invalid path returns false",
			modulePath: "/tmp/mei-me.ko",
			want:       "",
			wantOK:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := parseMEIModuleVersionFromPath(tt.modulePath)
			if ok != tt.wantOK {
				t.Fatalf("ok = %v, want %v", ok, tt.wantOK)
			}

			if got != tt.want {
				t.Fatalf("version = %q, want %q", got, tt.want)
			}
		})
	}
}
