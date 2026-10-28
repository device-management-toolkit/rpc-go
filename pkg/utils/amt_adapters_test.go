//go:build !windows

package utils

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParseInterfaceCarrier(t *testing.T) {
	tests := []struct {
		name    string
		carrier string
		want    string
	}{
		{name: "carrier present", carrier: "1\n", want: "up"},
		{name: "carrier absent", carrier: "0\n", want: "down"},
		{name: "invalid carrier", carrier: "unknown", want: ""},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assert.Equal(t, test.want, parseInterfaceCarrier(test.carrier))
		})
	}
}

func TestParseInterfaceOperstate(t *testing.T) {
	tests := []struct {
		name      string
		operstate string
		want      string
	}{
		{name: "operational", operstate: "up\n", want: "up"},
		{name: "disconnected", operstate: "down\n", want: "down"},
		{name: "lower layer disconnected", operstate: "lowerlayerdown\n", want: "down"},
		{name: "not present", operstate: "notpresent\n", want: "down"},
		{name: "unknown", operstate: "unknown\n", want: "unknown"},
		{name: "dormant", operstate: "dormant\n", want: "unknown"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assert.Equal(t, test.want, parseInterfaceOperstate(test.operstate))
		})
	}
}

func TestInterfaceLinkStatusFallsBackToUnknownWhenSysfsCannotBeRead(t *testing.T) {
	readErr := errors.New("sysfs unavailable")
	tests := []struct {
		name         string
		carrier      []byte
		carrierErr   error
		operstate    []byte
		operstateErr error
		want         string
	}{
		{name: "carrier takes precedence", carrier: []byte("1"), operstate: []byte("down"), want: "up"},
		{name: "carrier reports no link", carrier: []byte("0"), operstate: []byte("up"), want: "down"},
		{name: "operstate fallback", carrierErr: readErr, operstate: []byte("up"), want: "up"},
		{name: "unknown when both reads fail", carrierErr: readErr, operstateErr: readErr, want: "unknown"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assert.Equal(t, test.want, resolveInterfaceLinkStatus(test.carrier, test.carrierErr, test.operstate, test.operstateErr))
		})
	}
}
