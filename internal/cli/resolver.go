/*********************************************************************
 * Copyright (c) Intel Corporation 2024
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/

// Package cli provides Kong CLI configuration and YAML mapping
//
// Configuration Note:
// Kong-YAML supports loading configuration files that match the CLI structure.
// The YAML file should mirror the command hierarchy and flag names.
//
// For compatibility with existing config.yaml files, we recommend:
// 1. Use the new Kong-compatible config structure for new deployments
// 2. Migrate existing config.yaml files to the new structure
// 3. Use environment variables or CLI flags for one-off overrides

package cli

import (
	"os"
	"path/filepath"

	"github.com/alecthomas/kong"
	"github.com/device-management-toolkit/go-wsman-messages/v2/pkg/config"
	"gopkg.in/yaml.v3"
)

// ConfigResolver creates a resolver for backwards compatibility with existing config.yaml
// This is optional and only needed if you want to support old config files
func ConfigResolver(configPath string) (kong.Resolver, error) {
	// Check if config file exists
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		// Try absolute path
		if abs, err := filepath.Abs(configPath); err == nil {
			if _, err := os.Stat(abs); err == nil {
				configPath = abs
			} else {
				// No config file found, return empty resolver
				return kong.ResolverFunc(func(context *kong.Context, parent *kong.Path, flag *kong.Flag) (interface{}, error) {
					return nil, nil
				}), nil
			}
		}
	}

	// Read the config file
	configData, err := os.ReadFile(configPath)
	if err != nil {
		return nil, err
	}

	// Parse the existing config.yaml structure
	var config config.Configuration

	if err := yaml.Unmarshal(configData, &config); err != nil {
		return nil, err
	}

	// Create resolver that maps config values to Kong flags
	return kong.ResolverFunc(func(context *kong.Context, parent *kong.Path, flag *kong.Flag) (interface{}, error) {
		// Map configuration values to corresponding CLI flags
		switch flag.Name {
		case "amtPassword":
			// Use ACM password if available, fallback to CCM, then global password
			if config.Configuration.AMTSpecific.AdminPassword != "" {
				return config.Configuration.AMTSpecific.AdminPassword, nil
			}

		case "provisioningCert":
			if config.Configuration.AMTSpecific.ProvisioningCert != "" {
				return config.Configuration.AMTSpecific.ProvisioningCert, nil
			}

		case "provisioningCertPwd":
			if config.Configuration.AMTSpecific.ProvisioningCertPwd != "" {
				return config.Configuration.AMTSpecific.ProvisioningCertPwd, nil
			}

		case "skipIPRenew":
			// Map from wiredConfig.ipsync (inverse logic)
			return !config.Configuration.Network.Wired.IPSyncEnabled, nil
		}

		return nil, nil
	}), nil
}
