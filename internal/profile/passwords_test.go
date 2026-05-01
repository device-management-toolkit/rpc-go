/*********************************************************************
 * Copyright (c) Intel Corporation 2025
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/

package profile

import (
	"testing"

	"github.com/device-management-toolkit/go-wsman-messages/v2/pkg/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestResolvePasswords_ExplicitPasswords(t *testing.T) {
	cfg := config.Configuration{
		Configuration: config.RemoteManagement{
			AMTSpecific: config.AMTSpecific{
				AdminPassword:              "explicit-amt",
				GenerateRandomPassword:     false,
				MEBXPassword:               "explicit-mebx",
				GenerateRandomMEBXPassword: false,
				CIRA: config.CIRA{
					MPSPassword:            "explicit-mps",
					GenerateRandomPassword: false,
				},
			},
		},
	}

	amt, mebx, mps, err := ResolvePasswords(&cfg)
	require.NoError(t, err)
	assert.Equal(t, "explicit-amt", amt)
	assert.Equal(t, "explicit-mebx", mebx)
	assert.Equal(t, "explicit-mps", mps)
	// Config should remain unchanged
	assert.Equal(t, "explicit-amt", cfg.Configuration.AMTSpecific.AdminPassword)
	assert.Equal(t, "explicit-mebx", cfg.Configuration.AMTSpecific.MEBXPassword)
	assert.Equal(t, "explicit-mps", cfg.Configuration.AMTSpecific.CIRA.MPSPassword)
}

func TestResolvePasswords_GenerateAllRandom(t *testing.T) {
	cfg := config.Configuration{
		Configuration: config.RemoteManagement{
			AMTSpecific: config.AMTSpecific{
				GenerateRandomPassword:     true,
				GenerateRandomMEBXPassword: true,
				CIRA: config.CIRA{
					GenerateRandomPassword: true,
				},
			},
		},
	}

	amt, mebx, mps, err := ResolvePasswords(&cfg)
	require.NoError(t, err)

	// Passwords should have been generated (length 16)
	assert.Equal(t, 16, len(amt))
	assert.Equal(t, 16, len(mebx))
	assert.Equal(t, 16, len(mps))

	// Config should be updated with the generated passwords
	assert.Equal(t, amt, cfg.Configuration.AMTSpecific.AdminPassword)
	assert.Equal(t, mebx, cfg.Configuration.AMTSpecific.MEBXPassword)
	assert.Equal(t, mps, cfg.Configuration.AMTSpecific.CIRA.MPSPassword)
}

func TestResolvePasswords_GenerateOnlyAMT(t *testing.T) {
	cfg := config.Configuration{
		Configuration: config.RemoteManagement{
			AMTSpecific: config.AMTSpecific{
				GenerateRandomPassword:     true,
				MEBXPassword:               "static-mebx",
				GenerateRandomMEBXPassword: false,
				CIRA: config.CIRA{
					MPSPassword:            "static-mps",
					GenerateRandomPassword: false,
				},
			},
		},
	}

	amt, mebx, mps, err := ResolvePasswords(&cfg)
	require.NoError(t, err)

	assert.Equal(t, 16, len(amt))
	assert.Equal(t, "static-mebx", mebx)
	assert.Equal(t, "static-mps", mps)
}

func TestResolvePasswords_GenerateOnlyMEBX(t *testing.T) {
	cfg := config.Configuration{
		Configuration: config.RemoteManagement{
			AMTSpecific: config.AMTSpecific{
				AdminPassword:              "static-amt",
				GenerateRandomPassword:     false,
				GenerateRandomMEBXPassword: true,
				CIRA: config.CIRA{
					MPSPassword:            "static-mps",
					GenerateRandomPassword: false,
				},
			},
		},
	}

	amt, mebx, mps, err := ResolvePasswords(&cfg)
	require.NoError(t, err)

	assert.Equal(t, "static-amt", amt)
	assert.Equal(t, 16, len(mebx))
	assert.Equal(t, "static-mps", mps)
}

func TestResolvePasswords_GenerateOnlyMPS(t *testing.T) {
	cfg := config.Configuration{
		Configuration: config.RemoteManagement{
			AMTSpecific: config.AMTSpecific{
				AdminPassword:              "static-amt",
				GenerateRandomPassword:     false,
				MEBXPassword:               "static-mebx",
				GenerateRandomMEBXPassword: false,
				CIRA: config.CIRA{
					GenerateRandomPassword: true,
				},
			},
		},
	}

	amt, mebx, mps, err := ResolvePasswords(&cfg)
	require.NoError(t, err)

	assert.Equal(t, "static-amt", amt)
	assert.Equal(t, "static-mebx", mebx)
	assert.Equal(t, 16, len(mps))
}
