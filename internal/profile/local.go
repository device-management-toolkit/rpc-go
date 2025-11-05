/*********************************************************************
 * Copyright (c) Intel Corporation 2024
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/

package profile

import (
	"os"

	"github.com/device-management-toolkit/go-wsman-messages/v2/pkg/config"
	"gopkg.in/yaml.v3"
)

// LoadProfile loads a configuration from a YAML file
func LoadProfile(path string) (config.Configuration, error) {
	var profile config.Configuration

	// Read the file
	data, err := os.ReadFile(path)
	if err != nil {
		return profile, err
	}

	// Parse YAML
	err = yaml.Unmarshal(data, &profile)
	if err != nil {
		return profile, err
	}

	return profile, nil
}
