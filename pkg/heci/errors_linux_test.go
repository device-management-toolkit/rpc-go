//go:build linux

/*********************************************************************
 * Copyright (c) Intel Corporation 2026
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/

package heci

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestClassifyLinuxError(t *testing.T) {
	tests := []struct {
		name string
		err  error
		kind error
	}{
		{name: "permission denied", err: fs.ErrPermission, kind: ErrPermissionDenied},
		{name: "unsupported operation", err: syscall.ENOTTY, kind: ErrUnsupportedDevice},
		{name: "wrapped unsupported operation", err: fmt.Errorf("ioctl request: %w", syscall.ENOTTY), kind: ErrUnsupportedDevice},
		{name: "device node absent", err: fs.ErrNotExist, kind: ErrDeviceNotFound},
		{name: "errno device node absent", err: syscall.ENOENT, kind: ErrDeviceNotFound},
		{name: "no backing device", err: syscall.ENODEV, kind: ErrDeviceNotFound},
		{name: "no such device or address", err: syscall.ENXIO, kind: ErrDeviceNotFound},
		{name: "wrapped missing device", err: fmt.Errorf("open /dev/mei0: %w", syscall.ENODEV), kind: ErrDeviceNotFound},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			classified := classifyLinuxError(tt.err)

			assert.ErrorIs(t, classified, tt.kind)
			assert.ErrorIs(t, classified, tt.err)
		})
	}

	t.Run("does not classify unrelated error", func(t *testing.T) {
		want := errors.New("transient device error")

		assert.ErrorIs(t, classifyLinuxError(want), want)
		assert.NotErrorIs(t, classifyLinuxError(want), ErrUnsupportedDevice)
	})

	// EBUSY is the retryable case the connect loop backs off on. Classifying it
	// would make isPermanentHECIError treat a busy ME as fatal and skip retries.
	t.Run("does not classify busy device", func(t *testing.T) {
		classified := classifyLinuxError(syscall.EBUSY)

		assert.ErrorIs(t, classified, syscall.EBUSY)
		assert.NotErrorIs(t, classified, ErrDeviceNotFound)
		assert.NotErrorIs(t, classified, ErrUnsupportedDevice)
		assert.NotErrorIs(t, classified, ErrPermissionDenied)
	})

	t.Run("nil passes through", func(t *testing.T) {
		assert.NoError(t, classifyLinuxError(nil))
	})

	// Classification is applied at both openMEIDevicePath and connectClient, so
	// an already-classified error must not gain a second wrapper.
	t.Run("is idempotent", func(t *testing.T) {
		once := classifyLinuxError(syscall.ENODEV)
		twice := classifyLinuxError(once)

		assert.Equal(t, once.Error(), twice.Error())
		assert.ErrorIs(t, twice, ErrDeviceNotFound)
		assert.ErrorIs(t, twice, syscall.ENODEV)
	})
}

func TestOpenAndConnectClassifiesMissingDevice(t *testing.T) {
	originalPaths := meiDevicePaths
	meiDevicePaths = []string{filepath.Join(t.TempDir(), "missing-mei")}
	t.Cleanup(func() { meiDevicePaths = originalPaths })

	data := CMEIConnectClientData{data: MEI_IAMTHIF}
	err := (&Driver{}).openAndConnect(&data, 1, false)

	assert.ErrorIs(t, err, ErrDeviceNotFound)
	assert.ErrorIs(t, err, fs.ErrNotExist)
}

func TestOpenAndConnectClassifiesUnsupportedDevice(t *testing.T) {
	originalPaths := meiDevicePaths

	devicePath := filepath.Join(t.TempDir(), "not-mei")

	if err := os.WriteFile(devicePath, nil, 0o600); err != nil {
		t.Fatal(err)
	}

	meiDevicePaths = []string{devicePath}

	t.Cleanup(func() { meiDevicePaths = originalPaths })

	data := CMEIConnectClientData{data: MEI_IAMTHIF}
	err := (&Driver{}).openAndConnect(&data, 1, false)

	assert.ErrorIs(t, err, ErrUnsupportedDevice)
	assert.ErrorIs(t, err, syscall.ENOTTY)
}
