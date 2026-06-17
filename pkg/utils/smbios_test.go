/*********************************************************************
 * Copyright (c) Intel Corporation 2026
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/

package utils

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGetSMBIOSSystemUUID(t *testing.T) {
	orig := readSMBIOSUUIDFile
	origOS := currentGOOS
	origCmd := runSMBIOSUUIDCommand

	t.Cleanup(func() { readSMBIOSUUIDFile = orig })
	t.Cleanup(func() { currentGOOS = origOS })
	t.Cleanup(func() { runSMBIOSUUIDCommand = origCmd })

	currentGOOS = "linux"

	t.Run("valid UUID is normalized", func(t *testing.T) {
		readSMBIOSUUIDFile = func(_ string) ([]byte, error) {
			return []byte("D83E613D-3B03-6BC0-36BD-48210B3594EC\n"), nil
		}

		u, err := GetSMBIOSSystemUUID()
		require.NoError(t, err)
		assert.Equal(t, "d83e613d-3b03-6bc0-36bd-48210b3594ec", u)
	})

	t.Run("read failure", func(t *testing.T) {
		readSMBIOSUUIDFile = func(_ string) ([]byte, error) {
			return nil, errors.New("permission denied")
		}

		_, err := GetSMBIOSSystemUUID()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to read SMBIOS product UUID")
	})

	t.Run("invalid UUID format", func(t *testing.T) {
		readSMBIOSUUIDFile = func(_ string) ([]byte, error) {
			return []byte("not-a-uuid"), nil
		}

		_, err := GetSMBIOSSystemUUID()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid SMBIOS UUID")
	})

	t.Run("all-zero UUID rejected", func(t *testing.T) {
		readSMBIOSUUIDFile = func(_ string) ([]byte, error) {
			return []byte("00000000-0000-0000-0000-000000000000"), nil
		}

		_, err := GetSMBIOSSystemUUID()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "sentinel")
	})

	t.Run("all-ff UUID rejected", func(t *testing.T) {
		readSMBIOSUUIDFile = func(_ string) ([]byte, error) {
			return []byte("ffffffff-ffff-ffff-ffff-ffffffffffff"), nil
		}

		_, err := GetSMBIOSSystemUUID()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "sentinel")
	})

	t.Run("known-corrupted UUID rejected", func(t *testing.T) {
		readSMBIOSUUIDFile = func(_ string) ([]byte, error) {
			return []byte("03000200-0400-0500-0006-000700080009"), nil
		}

		_, err := GetSMBIOSSystemUUID()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "sentinel")
	})

	t.Run("windows fallback", func(t *testing.T) {
		currentGOOS = "windows"
		readSMBIOSUUIDFile = func(_ string) ([]byte, error) {
			return nil, errors.New("not available")
		}
		runSMBIOSUUIDCommand = func(name string, args ...string) ([]byte, error) {
			return []byte("D83E613D-3B03-6BC0-36BD-48210B3594EC\n"), nil
		}

		u, err := GetSMBIOSSystemUUID()
		require.NoError(t, err)
		assert.Equal(t, "d83e613d-3b03-6bc0-36bd-48210b3594ec", u)
	})

	t.Run("unsupported OS", func(t *testing.T) {
		currentGOOS = "unsupported-os"
		readSMBIOSUUIDFile = func(_ string) ([]byte, error) {
			return nil, errors.New("not available")
		}

		_, err := GetSMBIOSSystemUUID()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "not supported")
	})
}
