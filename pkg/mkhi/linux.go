//go:build !windows

/*********************************************************************
 * Copyright (c) Intel Corporation 2026
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/

package mkhi

import (
	"github.com/device-management-toolkit/rpc-go/v2/pkg/heci"
	log "github.com/sirupsen/logrus"
)

// NewCommand creates a new MKHI command for Linux.
func NewCommand() Interface {
	return &Command{
		Heci: heci.NewDriver(),
	}
}

// initGUID initializes the HECI driver with the MKHI client GUID.
func (c *Command) initGUID() error {
	if err := c.Heci.InitWithGUID(heci.MEI_MKHI); err != nil {
		log.Tracef("Failed to initialize MKHI MEI client: %v", err)

		return ErrMKHINotSupported
	}

	return nil
}
