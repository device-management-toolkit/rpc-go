/*********************************************************************
 * Copyright (c) Intel Corporation 2024
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/
package hotham

// HOTHAM Command Constants
// Reference: Intel MEI HOTHAM Interface Specification
const (
	// Flash Log Commands
	HOTHAM_CMD_GET_FLOG_SIZE = 0x80 // HothamCtlGetFlogSize: Id 0x80, 0x2
	HOTHAM_CMD_GET_FLOG      = 0x81 // HothamCtlGetFlog: Id 0x81, 0x2

	// Command Group
	HOTHAM_GROUP_ID = 0x02 // HTM_MSG_CLASS_COMMAND
)

// HOTHAMHeader represents the HOTHAM HECI message header
// This is a simplified 4-byte header structure for HOTHAM commands
type HOTHAMHeader struct {
	Command  uint8 // Command ID (e.g., 0x80, 0x81)
	Reserved uint8 // Reserved byte
	Group    uint8 // Group ID (0x02 for COMMAND class)
	Length   uint8 // Length of data following header
}

// GetFlogSizeRequest requests the size of the Flash Log
type GetFlogSizeRequest struct {
	Header HOTHAMHeader
}

// GetFlogSizeResponse contains the Flash Log size
type GetFlogSizeResponse struct {
	Header HOTHAMHeader
	Size   uint32 // Size of FLOG in bytes
}

// GetFlogRequest requests the Flash Log data
type GetFlogRequest struct {
	Header HOTHAMHeader
}

// GetFlogResponse contains the Flash Log data
// Note: The actual data follows the header
type GetFlogResponse struct {
	Header HOTHAMHeader
	Data   []byte
}
