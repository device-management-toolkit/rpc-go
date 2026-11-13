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

	t.Run("windows powershell fallback", func(t *testing.T) {
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

	t.Run("windows pwsh fallback when powershell fails", func(t *testing.T) {
		currentGOOS = "windows"
		readSMBIOSUUIDFile = func(_ string) ([]byte, error) {
			return nil, errors.New("not available")
		}

		callCount := 0

		runSMBIOSUUIDCommand = func(name string, args ...string) ([]byte, error) {
			callCount++

			if name == "powershell" || name == "powershell.exe" {
				return nil, errors.New("not found")
			}

			return []byte("D83E613D-3B03-6BC0-36BD-48210B3594EC\n"), nil
		}

		u, err := GetSMBIOSSystemUUID()
		require.NoError(t, err)
		assert.Equal(t, "d83e613d-3b03-6bc0-36bd-48210b3594ec", u)
		assert.GreaterOrEqual(t, callCount, 3, "should have tried powershell variants before pwsh")
	})

	t.Run("darwin reads IOPlatformUUID from ioreg", func(t *testing.T) {
		currentGOOS = "darwin"

		var gotName string

		runSMBIOSUUIDCommand = func(name string, args ...string) ([]byte, error) {
			gotName = name

			return []byte("+-o J314sAP  <class IOPlatformExpertDevice, registered, matched, active>\n" +
				"    {\n" +
				"      \"IOPlatformSerialNumber\" = \"C02ABC123DEF\"\n" +
				"      \"IOPlatformUUID\" = \"D83E613D-3B03-6BC0-36BD-48210B3594EC\"\n" +
				"      \"manufacturer\" = <\"Apple Inc.\">\n" +
				"    }\n"), nil
		}

		u, err := GetSMBIOSSystemUUID()
		require.NoError(t, err)
		assert.Equal(t, "d83e613d-3b03-6bc0-36bd-48210b3594ec", u)
		assert.Equal(t, "ioreg", gotName)
	})

	t.Run("darwin ioreg failure", func(t *testing.T) {
		currentGOOS = "darwin"
		runSMBIOSUUIDCommand = func(name string, args ...string) ([]byte, error) {
			return nil, errors.New("not found")
		}

		_, err := GetSMBIOSSystemUUID()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to query platform UUID on macOS")
	})

	t.Run("darwin ioreg output without IOPlatformUUID", func(t *testing.T) {
		currentGOOS = "darwin"
		runSMBIOSUUIDCommand = func(name string, args ...string) ([]byte, error) {
			return []byte("+-o J314sAP  <class IOPlatformExpertDevice>\n    {\n    }\n"), nil
		}

		_, err := GetSMBIOSSystemUUID()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "IOPlatformUUID not found")
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

func TestGetSystemSerialNumber(t *testing.T) {
	origFile := readSMBIOSUUIDFile
	origOS := currentGOOS
	origCmd := runSMBIOSUUIDCommand

	t.Cleanup(func() { readSMBIOSUUIDFile = origFile })
	t.Cleanup(func() { currentGOOS = origOS })
	t.Cleanup(func() { runSMBIOSUUIDCommand = origCmd })

	t.Run("linux reads product_serial", func(t *testing.T) {
		currentGOOS = goosLinux
		readSMBIOSUUIDFile = func(path string) ([]byte, error) {
			assert.Equal(t, productSerialPath, path)

			return []byte("PF4ABCDE\n"), nil
		}

		serial, err := GetSystemSerialNumber()
		require.NoError(t, err)
		assert.Equal(t, "PF4ABCDE", serial)
	})

	t.Run("linux read failure", func(t *testing.T) {
		currentGOOS = goosLinux
		readSMBIOSUUIDFile = func(_ string) ([]byte, error) {
			return nil, errors.New("permission denied")
		}

		_, err := GetSystemSerialNumber()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to read system serial number")
	})

	t.Run("linux placeholder is unavailable", func(t *testing.T) {
		currentGOOS = goosLinux
		readSMBIOSUUIDFile = func(_ string) ([]byte, error) {
			return []byte("To Be Filled By O.E.M.\n"), nil
		}

		_, err := GetSystemSerialNumber()
		assert.ErrorIs(t, err, ErrSerialNumberUnavailable)
	})

	t.Run("windows queries Win32_BIOS", func(t *testing.T) {
		currentGOOS = goosWindows
		runSMBIOSUUIDCommand = func(_ string, args ...string) ([]byte, error) {
			assert.Contains(t, args[len(args)-1], "Win32_BIOS")

			return []byte("45ZFVD3\r\n"), nil
		}

		serial, err := GetSystemSerialNumber()
		require.NoError(t, err)
		assert.Equal(t, "45ZFVD3", serial)
	})

	t.Run("windows falls back to the next PowerShell host", func(t *testing.T) {
		currentGOOS = goosWindows
		calls := 0
		runSMBIOSUUIDCommand = func(_ string, _ ...string) ([]byte, error) {
			calls++
			if calls == 1 {
				return nil, errors.New("not found")
			}

			return []byte("45ZFVD3"), nil
		}

		serial, err := GetSystemSerialNumber()
		require.NoError(t, err)
		assert.Equal(t, "45ZFVD3", serial)
		assert.Equal(t, 2, calls)
	})

	t.Run("windows query failure", func(t *testing.T) {
		currentGOOS = goosWindows
		runSMBIOSUUIDCommand = func(_ string, _ ...string) ([]byte, error) {
			return nil, errors.New("powershell missing")
		}

		_, err := GetSystemSerialNumber()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to read system serial number")
	})

	t.Run("macOS reads IOPlatformSerialNumber", func(t *testing.T) {
		currentGOOS = goosDarwin
		runSMBIOSUUIDCommand = func(_ string, _ ...string) ([]byte, error) {
			return []byte("    \"IOPlatformUUID\" = \"D83E613D-3B03-6BC0-36BD-48210B3594EC\"\n" +
				"    \"IOPlatformSerialNumber\" = \"C02ABC123XYZ\"\n"), nil
		}

		serial, err := GetSystemSerialNumber()
		require.NoError(t, err)
		assert.Equal(t, "C02ABC123XYZ", serial)
	})

	t.Run("macOS serial missing from ioreg output", func(t *testing.T) {
		currentGOOS = goosDarwin
		runSMBIOSUUIDCommand = func(_ string, _ ...string) ([]byte, error) {
			return []byte("    \"IOPlatformUUID\" = \"D83E613D-3B03-6BC0-36BD-48210B3594EC\"\n"), nil
		}

		_, err := GetSystemSerialNumber()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "IOPlatformSerialNumber not found")
	})

	t.Run("unsupported OS", func(t *testing.T) {
		currentGOOS = "plan9"

		_, err := GetSystemSerialNumber()
		assert.ErrorIs(t, err, ErrSerialNumberUnavailable)
	})
}

func TestSanitizeSerialNumber(t *testing.T) {
	serial, err := sanitizeSerialNumber("  PF4ABCDE \n")
	require.NoError(t, err)
	assert.Equal(t, "PF4ABCDE", serial)

	for _, placeholder := range []string{"", "   ", "To Be Filled By O.E.M.", "Default string", "System Serial Number", "0"} {
		_, err := sanitizeSerialNumber(placeholder)
		assert.ErrorIs(t, err, ErrSerialNumberUnavailable, placeholder)
	}
}
