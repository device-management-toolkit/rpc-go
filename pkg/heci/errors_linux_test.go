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
