/*********************************************************************
 * Copyright (c) Intel Corporation 2026
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/

package utils

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
)

const (
	productUUIDPath = "/sys/class/dmi/id/product_uuid"
	// productSerialPath is root-only readable; rpc-go already requires root for HECI.
	productSerialPath = "/sys/class/dmi/id/product_serial"
)

const (
	goosLinux   = "linux"
	goosWindows = "windows"
	goosDarwin  = "darwin"
)

const (
	ioPlatformUUIDKey         = `"IOPlatformUUID"`
	ioPlatformSerialNumberKey = `"IOPlatformSerialNumber"`
)

// ErrSerialNumberUnavailable means the platform reports no usable serial number.
var ErrSerialNumberUnavailable = errors.New("system serial number is not available")

// placeholderSerials are values OEMs commonly leave in SMBIOS when the serial
// number was never programmed. They are not unique and are treated as absent.
var placeholderSerials = []string{
	"",
	"0",
	"none",
	"n/a",
	"na",
	"default string",
	"not specified",
	"not applicable",
	"system serial number",
	"to be filled by o.e.m.",
	"to be filled by oem",
	"0123456789",
	"chassis serial number",
	"invalid",
}

var (
	readSMBIOSUUIDFile   = os.ReadFile
	currentGOOS          = runtime.GOOS
	runSMBIOSUUIDCommand = func(name string, args ...string) ([]byte, error) {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		return exec.CommandContext(ctx, name, args...).Output()
	}
)

// GetSMBIOSSystemUUID reads the system UUID from OS-exposed SMBIOS sources, or IOKit on macOS.
// Returns the UUID as a lowercase RFC 4122 string.
func GetSMBIOSSystemUUID() (string, error) {
	switch currentGOOS {
	case goosLinux:
		// Linux path: read UUID directly from DMI sysfs.
		raw, err := readSMBIOSUUIDFile(productUUIDPath)
		if err != nil {
			return "", fmt.Errorf("failed to read SMBIOS product UUID: %w", err)
		}

		return normalizeUUID(raw)
	case goosWindows:
		return getWindowsUUID()
	case goosDarwin:
		return getDarwinUUID()
	default:
		return "", fmt.Errorf("SMBIOS UUID lookup not supported on %s", currentGOOS)
	}
}

// GetSystemSerialNumber returns the OEM system serial number (SMBIOS System
// Information, Type 1), or the platform serial number from IOKit on macOS.
// This is the value Intel AMT reports through CIM_Chassis.SerialNumber, read
// from the host so it is available before activation. Placeholder values are
// reported as ErrSerialNumberUnavailable.
func GetSystemSerialNumber() (string, error) {
	var (
		raw []byte
		err error
	)

	switch currentGOOS {
	case goosLinux:
		raw, err = readSMBIOSUUIDFile(productSerialPath)
	case goosWindows:
		var product *windowsSystemProduct

		product, err = getWindowsSystemProduct()
		if err == nil {
			raw = []byte(product.serial)
		}
	case goosDarwin:
		raw, err = readDarwinPlatformValue(ioPlatformSerialNumberKey)
	default:
		return "", ErrSerialNumberUnavailable
	}

	if err != nil {
		return "", fmt.Errorf("failed to read system serial number: %w", err)
	}

	return sanitizeSerialNumber(string(raw))
}

// sanitizeSerialNumber trims the value and rejects well-known placeholders,
// including a serial made only of zeros.
func sanitizeSerialNumber(serial string) (string, error) {
	serial = strings.TrimSpace(strings.Trim(serial, "\x00"))
	if strings.Trim(serial, "0") == "" {
		return "", ErrSerialNumberUnavailable
	}

	lower := strings.ToLower(serial)

	for _, p := range placeholderSerials {
		if lower == p {
			return "", ErrSerialNumberUnavailable
		}
	}

	return serial, nil
}

func getWindowsUUID() (string, error) {
	product, err := getWindowsSystemProduct()
	if err != nil {
		return "", fmt.Errorf("failed to query UUID on Windows: %w", err)
	}

	return normalizeUUID([]byte(product.uuid))
}

// windowsSystemProductQuery reads the SMBIOS System Information (Type 1) UUID
// and serial number in one PowerShell start. Each value is labeled because a
// missing one prints an empty line.
const windowsSystemProductQuery = `$p = Get-CimInstance Win32_ComputerSystemProduct; "UUID=" + $p.UUID; "Serial=" + $p.IdentifyingNumber`

type windowsSystemProduct struct {
	uuid   string
	serial string
}

// The query result is kept for the life of the process so the UUID and the
// serial number never cost more than one PowerShell start between them.
var (
	windowsProductMu sync.Mutex
	windowsProduct   *windowsSystemProduct
)

func getWindowsSystemProduct() (*windowsSystemProduct, error) {
	windowsProductMu.Lock()
	defer windowsProductMu.Unlock()

	if windowsProduct != nil {
		return windowsProduct, nil
	}

	out, err := runWindowsCIMQuery(windowsSystemProductQuery)
	if err != nil {
		return nil, err
	}

	product := &windowsSystemProduct{}

	for _, line := range strings.Split(string(out), "\n") {
		name, value, found := strings.Cut(strings.TrimSpace(line), "=")
		if !found {
			continue
		}

		switch name {
		case "UUID":
			product.uuid = strings.TrimSpace(value)
		case "Serial":
			product.serial = strings.TrimSpace(value)
		}
	}

	windowsProduct = product

	return product, nil
}

// runWindowsCIMQuery runs psCmd with the first PowerShell host that works.
func runWindowsCIMQuery(psCmd string) ([]byte, error) {
	var lastErr error

	for _, ps := range []string{"powershell", "powershell.exe", "pwsh", "pwsh.exe"} {
		out, err := runSMBIOSUUIDCommand(ps, "-NoProfile", "-NonInteractive", "-Command", psCmd)
		if err == nil {
			return out, nil
		}

		lastErr = err
	}

	return nil, lastErr
}

// getDarwinUUID reads IOPlatformUUID, the hardware UUID macOS exposes in place of SMBIOS.
func getDarwinUUID() (string, error) {
	value, err := readDarwinPlatformValue(ioPlatformUUIDKey)
	if err != nil {
		return "", fmt.Errorf("failed to query platform UUID on macOS: %w", err)
	}

	return normalizeUUID(value)
}

// readDarwinPlatformValue returns the value of key from the IOPlatformExpertDevice registry entry.
func readDarwinPlatformValue(key string) ([]byte, error) {
	out, err := runSMBIOSUUIDCommand("ioreg", "-rd1", "-c", "IOPlatformExpertDevice")
	if err != nil {
		return nil, err
	}

	for _, line := range strings.Split(string(out), "\n") {
		name, value, found := strings.Cut(line, "=")
		if !found || strings.TrimSpace(name) != key {
			continue
		}

		return []byte(strings.Trim(strings.TrimSpace(value), `"`)), nil
	}

	return nil, fmt.Errorf("%s not found in ioreg output", strings.Trim(key, `"`))
}

func normalizeUUID(raw []byte) (string, error) {
	parsed, err := uuid.Parse(strings.TrimSpace(string(raw)))
	if err != nil {
		return "", fmt.Errorf("invalid SMBIOS UUID: %w", err)
	}

	normalized := strings.ToLower(parsed.String())
	if IsKnownInvalidUUID(normalized) {
		return "", fmt.Errorf("invalid SMBIOS UUID sentinel value")
	}

	return normalized, nil
}
