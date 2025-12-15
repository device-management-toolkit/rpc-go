//go:build windows
// +build windows

/*********************************************************************
 * Copyright (c) Intel Corporation 2024
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/

package upid

import (
	log "github.com/sirupsen/logrus"
)

// Client represents a Windows UPID client
type Client struct {
	// TODO: Add Windows-specific fields
}

// NewClient creates a new UPID client for Windows
func NewClient() Interface {
	return &Client{}
}

// GetUPID retrieves the Intel UPID from the platform
func (c *Client) GetUPID() (*UPID, error) {
	// TODO: Implement Windows UPID retrieval
	log.Warn("UPID support for Windows is not yet implemented")
	return nil, ErrUPIDNotSupported
}

// IsSupported checks if UPID is supported on this platform
func (c *Client) IsSupported() bool {
	// TODO: Implement Windows UPID support check
	return false
}

// Close releases resources held by the UPID client
func (c *Client) Close() error {
	return nil
}
