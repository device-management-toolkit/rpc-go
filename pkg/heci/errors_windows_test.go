//go:build windows

/*********************************************************************
 * Copyright (c) Intel Corporation 2026
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/

package heci

import (
	"errors"
	"fmt"
	"syscall"
	"testing"

	setupapi "github.com/device-management-toolkit/rpc-go/v2/pkg/windows"
	"github.com/stretchr/testify/assert"
	"golang.org/x/sys/windows"
)

func TestClassifyWindowsError(t *testing.T) {
	tests := []struct {
		name string
		err  error
		kind error
	}{
		{name: "device not found", err: windows.ERROR_NO_MORE_ITEMS, kind: ErrDeviceNotFound},
		{name: "permission denied", err: windows.ERROR_ACCESS_DENIED, kind: ErrPermissionDenied},
		{name: "unsupported operation", err: windows.ERROR_NOT_SUPPORTED, kind: ErrUnsupportedDevice},
		{name: "wrapped unsupported operation", err: fmt.Errorf("device ioctl: %w", windows.ERROR_INVALID_FUNCTION), kind: ErrUnsupportedDevice},
		// The interface path can go stale between enumeration and CreateFile.
		{name: "interface path missing", err: windows.ERROR_FILE_NOT_FOUND, kind: ErrDeviceNotFound},
		{name: "interface path unreachable", err: windows.ERROR_PATH_NOT_FOUND, kind: ErrDeviceNotFound},
		{name: "device removed", err: windows.ERROR_NO_SUCH_DEVICE, kind: ErrDeviceNotFound},
		{name: "device does not exist", err: windows.ERROR_DEV_NOT_EXIST, kind: ErrDeviceNotFound},
		{name: "wrapped missing interface", err: fmt.Errorf("CreateFile: %w", windows.ERROR_FILE_NOT_FOUND), kind: ErrDeviceNotFound},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			classified := classifyWindowsError(tt.err)

			assert.ErrorIs(t, classified, tt.kind)
			assert.ErrorIs(t, classified, tt.err)
		})
	}

	t.Run("does not classify unrelated error", func(t *testing.T) {
		want := errors.New("transient device error")

		assert.ErrorIs(t, classifyWindowsError(want), want)
		assert.NotErrorIs(t, classifyWindowsError(want), ErrDeviceNotFound)
	})

	t.Run("nil passes through", func(t *testing.T) {
		assert.NoError(t, classifyWindowsError(nil))
	})

	// FindDevices classifies via defer and doIoctl classifies inline, so a value
	// can pass through twice; it must not gain a second wrapper.
	t.Run("is idempotent", func(t *testing.T) {
		once := classifyWindowsError(windows.ERROR_ACCESS_DENIED)
		twice := classifyWindowsError(once)

		assert.Equal(t, once.Error(), twice.Error())
		assert.ErrorIs(t, twice, ErrPermissionDenied)
		assert.ErrorIs(t, twice, windows.ERROR_ACCESS_DENIED)
	})
}

// FindDevices returns ErrDeviceNotFound when SetupDiGetClassDevs hands back an
// invalid handle without an errno, which previously produced an untyped error
// that the classifier could not match on.
func TestFindDevicesClassifiesInvalidHandle(t *testing.T) {
	oldGetClassDevs := setupDiGetClassDevs

	t.Cleanup(func() { setupDiGetClassDevs = oldGetClassDevs })

	setupDiGetClassDevs = func(*windows.GUID, *uint16, syscall.Handle, uint32) (syscall.Handle, error) {
		return syscall.InvalidHandle, nil
	}

	err := (&Driver{}).FindDevices()

	assert.ErrorIs(t, err, ErrDeviceNotFound)
	assert.ErrorIs(t, err, windows.ERROR_INVALID_HANDLE)
}

func TestFindDevicesClassifiesNoInterface(t *testing.T) {
	oldGetClassDevs := setupDiGetClassDevs
	oldEnumDeviceInterfaces := setupDiEnumDeviceInterfaces
	oldDestroyDeviceInfoList := setupDiDestroyDeviceInfoList

	t.Cleanup(func() {
		setupDiGetClassDevs = oldGetClassDevs
		setupDiEnumDeviceInterfaces = oldEnumDeviceInterfaces
		setupDiDestroyDeviceInfoList = oldDestroyDeviceInfoList
	})

	setupDiGetClassDevs = func(*windows.GUID, *uint16, syscall.Handle, uint32) (syscall.Handle, error) {
		return 1, nil
	}
	setupDiEnumDeviceInterfaces = func(syscall.Handle, *setupapi.SpDevinfoData, *windows.GUID, uint32, *setupapi.SpDevInterfaceData) (syscall.Handle, error) {
		return 0, windows.ERROR_NO_MORE_ITEMS
	}
	setupDiDestroyDeviceInfoList = func(syscall.Handle) error { return nil }

	err := (&Driver{}).FindDevices()

	assert.ErrorIs(t, err, ErrDeviceNotFound)
	assert.ErrorIs(t, err, windows.ERROR_NO_MORE_ITEMS)
}
