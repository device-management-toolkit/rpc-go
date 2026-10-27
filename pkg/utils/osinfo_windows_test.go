//go:build windows

/*********************************************************************
 * Copyright (c) Intel Corporation 2026
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/
package utils

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestWindowsDistro(t *testing.T) {
	assert.Equal(t, "Windows 11 Enterprise 24H2", windowsDistro("Windows 10 Enterprise", "24H2", 26100))
	assert.Equal(t, "Windows 10 Pro 22H2", windowsDistro("Windows 10 Pro", "22H2", 19045))
	assert.Equal(t, "Windows Server 2022 Standard", windowsDistro("Windows Server 2022 Standard", "", 20348))
}
