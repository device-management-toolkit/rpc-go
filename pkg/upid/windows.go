//go:build windows

/*********************************************************************
 * Copyright (c) Intel Corporation 2026
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/

package upid

import (
	"errors"

	"github.com/device-management-toolkit/rpc-go/v2/pkg/heci"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sys/windows"
)

// NewCommand creates a new UPID command for Windows.
func NewCommand() Interface {
	return &Command{
		Heci: heci.NewDriver(),
	}
}

// initGUID initializes the HECI driver with the platform-specific UPID GUID.
func (c *Command) initGUID() error {
	upidGUID, err := windows.GUIDFromString(UPIDGUID)
	if err != nil {
		log.Tracef("Failed to parse UPID GUID: %v", err)

		return ErrConnectionFailed
	}

	err = c.Heci.InitWithGUID(upidGUID)
	if err != nil {
		log.Tracef("Failed to initialize UPID MEI client: %v", err)

		return classifyInitError(err, upidClientMissing(err))
	}

	return nil
}

// upidClientMissing reports whether err means the MEI device was reached but
// hosts no UPID client. The MEI driver fails the connect request with
// ERROR_INVALID_HANDLE (or ERROR_NOT_FOUND) in that case; a missing device or
// an access failure is not a missing client.
func upidClientMissing(err error) bool {
	if errors.Is(err, heci.ErrDeviceNotFound) || errors.Is(err, heci.ErrPermissionDenied) {
		return false
	}

	return errors.Is(err, heci.ErrUnsupportedDevice) ||
		errors.Is(err, windows.ERROR_INVALID_HANDLE) ||
		errors.Is(err, windows.ERROR_NOT_FOUND)
}
