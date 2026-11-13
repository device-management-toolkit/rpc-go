//go:build !windows

/*********************************************************************
 * Copyright (c) Intel Corporation 2026
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/

package upid

import (
	"errors"

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

		return classifyInitError(err, upidClientMissing(err))
	}

	return nil
}

// upidClientMissing reports whether err means the MEI device was reached but
// hosts no UPID client (the driver answers ENOTTY, classified by heci as
// ErrUnsupportedDevice).
func upidClientMissing(err error) bool {
	return errors.Is(err, heci.ErrUnsupportedDevice)
}
