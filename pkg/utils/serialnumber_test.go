/*********************************************************************
 * Copyright (c) Intel Corporation 2026
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/
package utils

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// smbiosStruct builds an SMBIOS structure from a formatted area and its strings.
func smbiosStruct(formatted []byte, strs ...string) []byte {
	out := append([]byte{}, formatted...)

	if len(strs) == 0 {
		return append(out, 0, 0)
	}

	for _, s := range strs {
		out = append(out, []byte(s)...)
		out = append(out, 0)
	}

	return append(out, 0)
}

func type1(serialIndex byte, strs ...string) []byte {
	// Type 1, length 0x1B, handle 0x0001, Manufacturer=1, Product=2, Version=3, Serial=serialIndex
	formatted := make([]byte, 0x1B)
	formatted[0] = smbiosTypeSystemInformation
	formatted[1] = 0x1B
	formatted[2] = 0x01
	formatted[4] = 1
	formatted[5] = 2
	formatted[6] = 3
	formatted[smbiosSystemSerialOffset] = serialIndex

	return smbiosStruct(formatted, strs...)
}

func TestParseSMBIOSSystemSerial(t *testing.T) {
	bios := smbiosStruct([]byte{0, 0x12, 0x00, 0x00, 1, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, "Vendor", "1.0")
	end := smbiosStruct([]byte{smbiosTypeEndOfTable, 4, 0xFF, 0xFF})

	t.Run("finds Type 1 serial after other structures", func(t *testing.T) {
		table := append(append(append([]byte{}, bios...), type1(4, "Intel", "NUC", "1.0", "PF4ABCDE")...), end...)

		serial, err := parseSMBIOSSystemSerial(table)
		assert.NoError(t, err)
		assert.Equal(t, "PF4ABCDE", serial)
	})

	t.Run("serial string index 0 means not set", func(t *testing.T) {
		table := append(type1(0, "Intel", "NUC", "1.0"), end...)

		_, err := parseSMBIOSSystemSerial(table)
		assert.ErrorIs(t, err, ErrSerialNumberUnavailable)
	})

	t.Run("serial string index out of range", func(t *testing.T) {
		table := append(type1(9, "Intel"), end...)

		_, err := parseSMBIOSSystemSerial(table)
		assert.ErrorIs(t, err, ErrSerialNumberUnavailable)
	})

	t.Run("no Type 1 structure", func(t *testing.T) {
		_, err := parseSMBIOSSystemSerial(append(append([]byte{}, bios...), end...))
		assert.ErrorIs(t, err, ErrSerialNumberUnavailable)
	})

	t.Run("truncated table", func(t *testing.T) {
		_, err := parseSMBIOSSystemSerial([]byte{1, 0x1B, 0})
		assert.ErrorIs(t, err, ErrSerialNumberUnavailable)
	})
}

func TestSanitizeSerialNumber(t *testing.T) {
	serial, err := sanitizeSerialNumber("  PF4ABCDE \n")
	assert.NoError(t, err)
	assert.Equal(t, "PF4ABCDE", serial)

	for _, placeholder := range []string{"", "   ", "To Be Filled By O.E.M.", "Default string", "System Serial Number", "0"} {
		_, err := sanitizeSerialNumber(placeholder)
		assert.ErrorIs(t, err, ErrSerialNumberUnavailable, placeholder)
	}
}
