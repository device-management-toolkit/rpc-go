//go:build !windows

/*********************************************************************
 * Copyright (c) Intel Corporation 2026
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/

package psr

import (
	"github.com/device-management-toolkit/rpc-go/v2/pkg/heci"
	log "github.com/sirupsen/logrus"
)

// MEIPSRGUID is the Intel PSR MEI client GUID in the byte order the Linux MEI
// driver expects (see heci.MEI_UPID / heci.MEI_HOTHAM for the encoding).
//
// UNVERIFIED — not yet populated. Fill from the Intel PSR sample application,
// together with PSRGUID in types.go. While it is all-zero, initGUID fails fast
// with ErrPSRGUIDNotConfigured.
var MEIPSRGUID = [16]uint8{}

// NewCommand creates a new PSR command for Linux.
func NewCommand() Interface {
	return &Command{
		Heci: heci.NewDriver(),
	}
}

// guidConfigured reports whether a real PSR client GUID has been set.
func guidConfigured() bool {
	return MEIPSRGUID != [16]uint8{}
}

// initGUID initializes the HECI driver with the platform-specific PSR GUID.
func (c *Command) initGUID() error {
	if !guidConfigured() {
		return ErrPSRGUIDNotConfigured
	}

	err := c.Heci.InitWithGUID(MEIPSRGUID)
	if err != nil {
		log.Tracef("Failed to initialize PSR MEI client: %v", err)

		return ErrPSRNotSupported
	}

	return nil
}
