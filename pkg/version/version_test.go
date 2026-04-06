/*********************************************************************
 * Copyright (c) Intel Corporation 2025
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/

package version

import (
	"encoding/json"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGet_ReturnsInfo(t *testing.T) {
	info := Get()

	assert.NotEmpty(t, info.App, "App should not be empty")
	assert.NotEmpty(t, info.Version, "Version should not be empty")
	assert.NotEmpty(t, info.Protocol, "Protocol should not be empty")
	assert.NotEmpty(t, info.Commit, "Commit should not be empty")
	assert.NotEmpty(t, info.Date, "Date should not be empty")
	assert.Equal(t, runtime.Version(), info.Go)
	assert.Equal(t, runtime.GOOS+"/"+runtime.GOARCH, info.Platform)
}

func TestGet_JSONTags(t *testing.T) {
	info := Get()

	// Marshal and unmarshal to verify JSON tags work correctly
	data, err := json.Marshal(info)
	assert.NoError(t, err)

	var parsed map[string]string

	err = json.Unmarshal(data, &parsed)
	assert.NoError(t, err)

	expectedKeys := []string{"app", "version", "protocol", "commit", "date", "go", "platform"}
	for _, key := range expectedKeys {
		assert.Contains(t, parsed, key, "JSON output should contain %s", key)
	}
}
