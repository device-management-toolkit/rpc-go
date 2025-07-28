/*********************************************************************
 * Copyright (c) Intel Corporation 2024
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/

package config

import (
	"os"

	"github.com/device-management-toolkit/go-wsman-messages/v2/pkg/config"
	"gopkg.in/yaml.v3"
)

// LoadConfig loads a configuration from a YAML file
func LoadConfig(path string) (config.Configuration, error) {
	var config config.Configuration

	// Read the file
	data, err := os.ReadFile(path)
	if err != nil {
		return config, err
	}

	// Parse YAML
	err = yaml.Unmarshal(data, &config)
	if err != nil {
		return config, err
	}

	return config, nil
}
