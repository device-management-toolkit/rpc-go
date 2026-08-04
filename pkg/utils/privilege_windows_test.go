//go:build windows

package utils

import "testing"

func TestEscapeCmdMetachars(t *testing.T) {
	tests := []struct {
		name, in, want string
	}{
		{"plain", `C:\rpc\rpc.exe`, `C:\rpc\rpc.exe`},
		{"bare metachar escaped", `hunt&er`, `hunt^&er`},
		{"metachar inside quotes left alone", `"hunt&er now"`, `"hunt&er now"`},
		{"quoted path untouched", `"C:\Program Files\rpc.exe"`, `"C:\Program Files\rpc.exe"`},
		{"pipe and redirect outside quotes", `a|b>c`, `a^|b^>c`},
		{"parens outside quotes", `a(b)c`, `a^(b^)c`},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			if got := escapeCmdMetachars(tt.in); got != tt.want {
				t.Errorf("escapeCmdMetachars(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}
