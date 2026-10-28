//go:build windows

/*********************************************************************
 * Copyright (c) Intel Corporation 2026
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/

package mkhi

import (
	"github.com/device-management-toolkit/rpc-go/v2/pkg/heci"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sys/windows"
)

// NewCommand creates a new MKHI command for Windows.
func NewCommand() Interface {
	return &Command{
		Heci: heci.NewDriver(),
	}
}

// initGUID initializes the HECI driver with the MKHI client GUID.
func (c *Command) initGUID() error {
	guid, err := windows.GUIDFromString(MKHIGUID)
	if err != nil {
		log.Tracef("Failed to parse MKHI GUID: %v", err)

		return ErrMKHINotSupported
	}

	if err := c.Heci.InitWithGUID(guid); err != nil {
		log.Tracef("Failed to initialize MKHI MEI client: %v", err)

		return ErrMKHINotSupported
	}

	return nil
}
