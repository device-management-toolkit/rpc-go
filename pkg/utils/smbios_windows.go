//go:build windows

/*********************************************************************
 * Copyright (c) Intel Corporation 2026
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/
package utils

import (
	"errors"
	"unsafe"

	"golang.org/x/sys/windows"
)

// 'RSMB' firmware table provider signature.
const rsmbProvider = 'R'<<24 | 'S'<<16 | 'M'<<8 | 'B'

// rawSMBIOSDataHeaderSize is the size of the RawSMBIOSData header that
// precedes the structure table in a GetSystemFirmwareTable('RSMB') result.
const rawSMBIOSDataHeaderSize = 8

var procGetSystemFirmwareTable = windows.NewLazySystemDLL("kernel32.dll").NewProc("GetSystemFirmwareTable")

func getPlatformSerialNumber() (string, error) {
	size, _, err := procGetSystemFirmwareTable.Call(rsmbProvider, 0, 0, 0)
	if size == 0 {
		return "", err
	}

	buf := make([]byte, size)

	n, _, err := procGetSystemFirmwareTable.Call(rsmbProvider, 0, uintptr(unsafe.Pointer(&buf[0])), size)
	if n == 0 || n > size {
		return "", err
	}

	buf = buf[:n]
	if len(buf) < rawSMBIOSDataHeaderSize {
		return "", errors.New("SMBIOS firmware table is too short")
	}

	return parseSMBIOSSystemSerial(buf[rawSMBIOSDataHeaderSize:])
}
