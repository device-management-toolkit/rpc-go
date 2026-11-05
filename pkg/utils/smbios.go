/*********************************************************************
 * Copyright (c) Intel Corporation 2026
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/
package utils

import (
	"errors"
	"strings"
)

const (
	smbiosTypeSystemInformation = 1
	smbiosTypeEndOfTable        = 127
	// Offset of the Serial Number string index within the SMBIOS Type 1 structure.
	smbiosSystemSerialOffset = 0x07
)

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

// GetSystemSerialNumber returns the platform serial number from SMBIOS
// (System Information, Type 1). This is the same value Intel AMT reports
// through CIM_Chassis.SerialNumber, but it can be read from the host without
// WS-Management credentials, so it is available before activation.
func GetSystemSerialNumber() (string, error) {
	serial, err := getPlatformSerialNumber()
	if err != nil {
		return "", err
	}

	return sanitizeSerialNumber(serial)
}

// sanitizeSerialNumber trims the value and rejects well-known placeholders.
func sanitizeSerialNumber(serial string) (string, error) {
	serial = strings.TrimSpace(strings.Trim(serial, "\x00"))
	lower := strings.ToLower(serial)

	for _, p := range placeholderSerials {
		if lower == p {
			return "", ErrSerialNumberUnavailable
		}
	}

	return serial, nil
}

// parseSMBIOSSystemSerial walks a raw SMBIOS structure table and returns the
// Serial Number string of the first System Information (Type 1) structure.
func parseSMBIOSSystemSerial(table []byte) (string, error) {
	for i := 0; i+4 <= len(table); {
		structType := table[i]
		length := int(table[i+1])

		if length < 4 || i+length > len(table) {
			break
		}

		// The string-set follows the formatted area and ends with a double NUL.
		stringsStart := i + length

		end := stringsStart
		for end+1 < len(table) && (table[end] != 0 || table[end+1] != 0) {
			end++
		}

		if structType == smbiosTypeSystemInformation {
			if length <= smbiosSystemSerialOffset {
				return "", ErrSerialNumberUnavailable
			}

			return smbiosString(table[stringsStart:end], table[i+smbiosSystemSerialOffset])
		}

		if structType == smbiosTypeEndOfTable {
			break
		}

		i = end + 2
	}

	return "", ErrSerialNumberUnavailable
}

// smbiosString returns the 1-based string at index from an SMBIOS string-set.
func smbiosString(stringSet []byte, index byte) (string, error) {
	if index == 0 {
		return "", ErrSerialNumberUnavailable
	}

	parts := strings.Split(string(stringSet), "\x00")
	if int(index) > len(parts) {
		return "", ErrSerialNumberUnavailable
	}

	return parts[index-1], nil
}
