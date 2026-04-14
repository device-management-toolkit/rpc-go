//go:build !windows

/*********************************************************************
 * Copyright (c) Intel Corporation 2026
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/

package upid

import (
	"github.com/device-management-toolkit/rpc-go/v2/pkg/heci"
	log "github.com/sirupsen/logrus"
)

// NewCommand creates a new UPID command for Linux.
func NewCommand() Interface {
	return &Command{
		Heci: heci.NewDriver(),
	}
}

// initGUID initializes the HECI driver with the platform-specific UPID GUID.
func (c *Command) initGUID() error {
	err := c.Heci.InitWithGUID(heci.MEI_UPID)
	if err != nil {
		log.Tracef("Failed to initialize UPID MEI client: %v", err)

		return ErrUPIDNotSupported
	}

	return nil
}
