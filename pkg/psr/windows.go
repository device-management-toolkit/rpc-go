//go:build windows

/*********************************************************************
 * Copyright (c) Intel Corporation 2026
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/

package psr

import (
	"github.com/device-management-toolkit/rpc-go/v2/pkg/heci"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sys/windows"
)

// NewCommand creates a new PSR command for Windows.
func NewCommand() Interface {
	return &Command{
		Heci: heci.NewDriver(),
	}
}

// guidConfigured reports whether a real PSR client GUID has been set.
func guidConfigured() bool {
	return PSRGUID != ""
}

// initGUID initializes the HECI driver with the platform-specific PSR GUID.
func (c *Command) initGUID() error {
	if !guidConfigured() {
		return ErrPSRGUIDNotConfigured
	}

	psrGUID, err := windows.GUIDFromString(PSRGUID)
	if err != nil {
		log.Tracef("Failed to parse PSR GUID: %v", err)

		return ErrConnectionFailed
	}

	err = c.Heci.InitWithGUID(psrGUID)
	if err != nil {
		log.Tracef("Failed to initialize PSR MEI client: %v", err)

		return ErrPSRNotSupported
	}

	return nil
}
