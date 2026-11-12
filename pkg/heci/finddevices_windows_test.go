//go:build windows

/*********************************************************************
 * Copyright (c) Intel Corporation 2026
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/

package heci

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"golang.org/x/sys/windows"
)

var (
	errVersionFailed = errors.New("version ioctl failed")
	errConnectFailed = errors.New("connect ioctl failed")
)

// fakeMEIHandle stands in for an opened MEI device; no test opens a real one.
const fakeMEIHandle windows.Handle = 0x1234

func TestConnectOpenedDevice(t *testing.T) {
	ok := func() error { return nil }
	failVersion := func() error { return errVersionFailed }
	failConnect := func() error { return errConnectFailed }

	tests := []struct {
		name       string
		steps      []func() error
		wantErr    error
		wantClosed []windows.Handle
		wantHandle windows.Handle
	}{
		{
			name: "both steps succeed", steps: []func() error{ok, ok},
			wantHandle: fakeMEIHandle,
		},
		{
			name: "version query fails", steps: []func() error{failVersion, ok},
			wantErr: errVersionFailed, wantClosed: []windows.Handle{fakeMEIHandle},
		},
		{
			name: "client connect fails", steps: []func() error{ok, failConnect},
			wantErr: errConnectFailed, wantClosed: []windows.Handle{fakeMEIHandle},
		},
	}

	for _, tt := range tests {
		tt := tt

		t.Run(tt.name, func(t *testing.T) {
			oldClose := closeMEIHandle

			t.Cleanup(func() { closeMEIHandle = oldClose })

			var closed []windows.Handle

			closeMEIHandle = func(h windows.Handle) error {
				closed = append(closed, h)

				return nil
			}

			h := &Driver{meiDevice: fakeMEIHandle}
			err := h.connectOpenedDevice(tt.steps...)

			assert.ErrorIs(t, err, tt.wantErr)
			assert.Equal(t, tt.wantClosed, closed)
			assert.Equal(t, tt.wantHandle, h.meiDevice)
		})
	}
}

func TestConnectOpenedDeviceStopsAtTheFailedStep(t *testing.T) {
	oldClose := closeMEIHandle

	t.Cleanup(func() { closeMEIHandle = oldClose })

	closeMEIHandle = func(windows.Handle) error { return errConnectFailed }

	secondRan := false

	h := &Driver{meiDevice: fakeMEIHandle}
	err := h.connectOpenedDevice(
		func() error { return errVersionFailed },
		func() error {
			secondRan = true

			return nil
		},
	)

	// A close failure is only logged, so the step's error is returned.
	assert.ErrorIs(t, err, errVersionFailed)
	assert.False(t, secondRan)
	assert.Equal(t, windows.Handle(0), h.meiDevice)
}
