/*********************************************************************
 * Copyright (c) Intel Corporation 2026
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/

// Package hotham implements CSME Flash Log (FLOG) retrieval commands.
//
// Implementation Details:
// - Connects via HOTHAM GUID: {082EE5A7-7C25-470A-9643-0C06F0466EA1}
// - Uses 4-byte HOTHAM_HECI_HEADER (bit-packed into 32 bits)
// - Commands: GetFlogSize (0x80), GetFlog (0x81)

package hotham

import (
	"encoding/binary"
)

// FLOG Protocol Constants
const (
	// Flash Log Commands (ReqCode values)
	PCH_DFX_FLOG_GET_SIZE = 0x80 // GetFlogSize command
	PCH_DFX_FLOG_GET_LOG  = 0x81 // GetFlog command

	// HOTHAM Message Classes
	HTM_MSG_CLASS_COMMAND = 2 // Command message class

	// Target Silicon ID
	HTM_TARGET_ID = 1 // Target Silicon ID

	// FLOG response size
	FLOG_DATA_SIZE = 8192 // Flash log data size (8196 - 4-byte header)
)

// HOTHAMHeader represents the HOTHAM HECI message header (4 bytes total)
// This is a bit-packed structure used for CSME FLOG commands
// The entire header is packed into 32 bits (4 bytes)
type HOTHAMHeader struct {
	MsgClass   uint8  // 2 bits: Message class (HTM_MSG_CLASS_COMMAND = 2)
	TargetId   uint8  // 3 bits: Target Silicon ID (1)
	SequenceNo uint8  // 3 bits: Sequence number (0)
	ReqCode    uint8  // 8 bits: Request/Response opcode (0x80, 0x81)
	MsgLength  uint16 // 12 bits: Message length (0 for requests)
	Reserved   uint8  // 3 bits: Reserved (0)
	HeaderType uint8  // 1 bit: Header type (0)
}

// Pack encodes the HOTHAM header into a 4-byte buffer
// The HOTHAM_HECI_HEADER is bit-packed into 32 bits (4 bytes)
func (h *HOTHAMHeader) Pack() []byte {
	buf := make([]byte, 4)

	// Pack first 32 bits: MsgClass(2) | TargetId(3) | SequenceNo(3) | ReqCode(8) | MsgLength(12) | Reserved(3) | HeaderType(1)
	var header32 uint32

	header32 |= uint32(h.MsgClass&0x3) << 0     // bits 0-1
	header32 |= uint32(h.TargetId&0x7) << 2     // bits 2-4
	header32 |= uint32(h.SequenceNo&0x7) << 5   // bits 5-7
	header32 |= uint32(h.ReqCode&0xFF) << 8     // bits 8-15
	header32 |= uint32(h.MsgLength&0xFFF) << 16 // bits 16-27
	header32 |= uint32(h.Reserved&0x7) << 28    // bits 28-30
	header32 |= uint32(h.HeaderType&0x1) << 31  // bit 31

	// Write as little-endian (Intel architecture)
	binary.LittleEndian.PutUint32(buf[0:4], header32)

	return buf
}

// Unpack decodes a 4-byte buffer into the HOTHAM header
func (h *HOTHAMHeader) Unpack(buf []byte) {
	if len(buf) < 4 {
		return
	}

	// Read first 32 bits
	header32 := binary.LittleEndian.Uint32(buf[0:4])

	// Extract bit fields
	h.MsgClass = uint8((header32 >> 0) & 0x3)
	h.TargetId = uint8((header32 >> 2) & 0x7)
	h.SequenceNo = uint8((header32 >> 5) & 0x7)
	h.ReqCode = uint8((header32 >> 8) & 0xFF)
	h.MsgLength = uint16((header32 >> 16) & 0xFFF)
	h.Reserved = uint8((header32 >> 28) & 0x7)
	h.HeaderType = uint8((header32 >> 31) & 0x1)
}

// NewHOTHAMHeader creates a new HOTHAM header for FLOG commands
func NewHOTHAMHeader(reqCode uint8) HOTHAMHeader {
	return HOTHAMHeader{
		MsgClass:   HTM_MSG_CLASS_COMMAND, // 2
		TargetId:   HTM_TARGET_ID,         // 1
		SequenceNo: 0,                     // 0
		ReqCode:    reqCode,               // 0x80 or 0x81
		MsgLength:  0,                     // 0 for requests
		Reserved:   0,                     // 0
		HeaderType: 0,                     // 0
	}
}

// GetFlogSizeRequest requests the size of the Flash Log
type GetFlogSizeRequest struct {
	Header HOTHAMHeader
}

// GetFlogSizeResponse contains the Flash Log size
type GetFlogSizeResponse struct {
	Header HOTHAMHeader
	Size   uint16 // Size in bytes
}

// GetFlogRequest requests the Flash Log data
type GetFlogRequest struct {
	Header HOTHAMHeader
}

// GetFlogResponse contains the Flash Log data
type GetFlogResponse struct {
	Header HOTHAMHeader
	Data   []byte
}
