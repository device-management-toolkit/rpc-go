/*********************************************************************
 * Copyright (c) Intel Corporation 2026
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/
package utils

import (
	"runtime"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParseOSReleasePrettyName(t *testing.T) {
	content := "NAME=\"Ubuntu\"\nVERSION_ID=\"24.04\"\nPRETTY_NAME=\"Ubuntu 24.04.1 LTS\"\nID=ubuntu\n"
	assert.Equal(t, "Ubuntu 24.04.1 LTS", parseOSReleasePrettyName(strings.NewReader(content)))
	assert.Equal(t, "Fedora Linux 40", parseOSReleasePrettyName(strings.NewReader("PRETTY_NAME='Fedora Linux 40'")))
	assert.Empty(t, parseOSReleasePrettyName(strings.NewReader("NAME=Ubuntu\n")))
}

func TestGetOSInfo(t *testing.T) {
	info := GetOSInfo()
	assert.Equal(t, runtime.GOOS, info.Name)
	assert.NotEmpty(t, info.Version)
}
