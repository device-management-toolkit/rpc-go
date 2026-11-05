//go:build linux

/*********************************************************************
 * Copyright (c) Intel Corporation 2026
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/
package utils

import (
	"os"
)

const (
	dmiProductSerialPath = "/sys/class/dmi/id/product_serial"
	dmiTablePath         = "/sys/firmware/dmi/tables/DMI"
)

var readDMIFile = os.ReadFile

func getPlatformSerialNumber() (string, error) {
	// product_serial is root-only readable; rpc-go already requires root for HECI.
	if raw, err := readDMIFile(dmiProductSerialPath); err == nil {
		return string(raw), nil
	}

	table, err := readDMIFile(dmiTablePath)
	if err != nil {
		return "", err
	}

	return parseSMBIOSSystemSerial(table)
}
