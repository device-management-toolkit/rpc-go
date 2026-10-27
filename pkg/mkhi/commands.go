/*********************************************************************
 * Copyright (c) Intel Corporation 2026
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/

// Package mkhi talks to the CSME ME Kernel Host Interface (MKHI) client. It
// currently reads the firmware capabilities (FW caps SKU rule), which report
// which CSME features the SKU is entitled to, e.g. Trusted Endpoint
// Provisioning.
package mkhi

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/device-management-toolkit/rpc-go/v2/pkg/heci"
	log "github.com/sirupsen/logrus"
)

// MKHIGUID is the MKHI MEI client GUID.
const MKHIGUID = "{8E6A6715-9ABC-4043-88EF-9E39C6F63E0F}"

// MKHI message identifiers.
const (
	GroupIDFWCaps  uint8 = 0x03 // MKHI_GROUP_ID_FWCAPS
	CommandGetRule uint8 = 0x02 // FWCAPS_GET_RULE_CMD

	// RuleIDFWCapsSKU is MEFWCAPS_SKU_RULE_ID: feature ID 0 (kernel), rule 0.
	RuleIDFWCapsSKU uint32 = 0
)

// FWCapabilities is the FW caps SKU rule bitmask (FWCAPS_*_SKU_BIT).
type FWCapabilities uint32

// FW caps bits. Bit meanings can differ between platform generations; see TEPSupported.
const (
	FWCapsManageabilityFull FWCapabilities = 1 << 0
	FWCapsStandardManage    FWCapabilities = 1 << 1
	FWCapsAMT               FWCapabilities = 1 << 2
	FWCapsOneClickRecovery  FWCapabilities = 1 << 3
	FWCapsRemotePlatErase   FWCapabilities = 1 << 4
	FWCapsPSR               FWCapabilities = 1 << 5
	FWCapsKVM               FWCapabilities = 1 << 18
	// FWCapsTEP is FWCAPS_TPP_SKU_BIT (Trusted Endpoint Provisioning) on CSME 18
	// (Meteor Lake) and later. On CSME 16 the same bit means Wireless Display.
	FWCapsTEP  FWCapabilities = 1 << 24
	FWCapsUPID FWCapabilities = 1 << 28
	FWCapsPTT  FWCapabilities = 1 << 29
)

// Has reports whether every bit in c is set.
func (f FWCapabilities) Has(c FWCapabilities) bool {
	return f&c == c
}

// minTEPCSMEMajor is the first CSME major version (Meteor Lake) where FW caps bit 24 means TEP.
const minTEPCSMEMajor = 18

// TEPSupported reports whether Trusted Endpoint Provisioning is supported:
// CSME major version 18 or later with the TEP FW caps bit set. The version
// check matters because bit 24 has a different meaning before CSME 18.
func TEPSupported(csmeMajor int, caps FWCapabilities) bool {
	return csmeMajor >= minTEPCSMEMajor && caps.Has(FWCapsTEP)
}

// Interface defines the MKHI operations.
type Interface interface {
	// GetFWCapabilities reads the FW caps SKU rule.
	GetFWCapabilities() (FWCapabilities, error)
}

// Command wraps a HECI interface for MKHI operations.
type Command struct {
	Heci heci.Interface
}

var _ Interface = (*Command)(nil)

var (
	// ErrMKHINotSupported is returned when the MKHI MEI client cannot be opened.
	ErrMKHINotSupported = errors.New("MKHI MEI client not available")
	// ErrInvalidResponse is returned for malformed MKHI responses.
	ErrInvalidResponse = errors.New("invalid response from MKHI MEI client")
	// ErrCommandFailed is returned when the firmware reports a non-zero MKHI result.
	ErrCommandFailed = errors.New("MKHI command failed")
)

// header is mkhi_message_header_t: group_id:8, command:7, is_response:1, reserved:8, result:8.
type header uint32

const (
	commandShift    = 8
	commandMask     = 0x7F
	isResponseShift = 15
	resultShift     = 24
	byteMask        = 0xFF
)

func newHeader(group, command uint8) header {
	return header(uint32(group) | uint32(command&commandMask)<<commandShift)
}

func (h header) group() uint8     { return uint8(h & byteMask) }
func (h header) command() uint8   { return uint8((h >> commandShift) & commandMask) }
func (h header) isResponse() bool { return (h>>isResponseShift)&1 == 1 }
func (h header) result() uint8    { return uint8((h >> resultShift) & byteMask) }

type getRuleRequest struct {
	Header header
	RuleID uint32
}

// getRuleResponse is FWCAPS_GET_RULE_ACK with a 4-byte rule.
type getRuleResponse struct {
	Header      header
	RuleID      uint32
	RuleDataLen uint8
	RuleData    uint32
}

// GetFWCapabilities sends FWCAPS_GET_RULE for MEFWCAPS_SKU_RULE_ID.
func (c *Command) GetFWCapabilities() (FWCapabilities, error) {
	if err := c.initGUID(); err != nil {
		return 0, err
	}
	defer c.Heci.Close()

	req := getRuleRequest{Header: newHeader(GroupIDFWCaps, CommandGetRule), RuleID: RuleIDFWCapsSKU}

	var buf bytes.Buffer
	if err := binary.Write(&buf, binary.LittleEndian, &req); err != nil {
		return 0, err
	}

	size := uint32(buf.Len())

	written, err := c.Heci.SendMessage(buf.Bytes(), &size)
	if err != nil {
		return 0, fmt.Errorf("%w: send: %w", ErrCommandFailed, err)
	}

	if written != buf.Len() {
		return 0, fmt.Errorf("%w: incomplete request sent: %d/%d bytes", ErrCommandFailed, written, buf.Len())
	}

	bufferSize := c.Heci.GetBufferSize()
	response := make([]byte, bufferSize)

	n, err := c.Heci.ReceiveMessage(response, &bufferSize)
	if err != nil {
		return 0, fmt.Errorf("%w: receive: %w", ErrCommandFailed, err)
	}

	log.Tracef("MKHI GET_RULE response: %d bytes: %x", n, response[:n])

	return parseGetRuleResponse(response[:n])
}

func parseGetRuleResponse(b []byte) (FWCapabilities, error) {
	var resp getRuleResponse

	if len(b) < binary.Size(resp) {
		return 0, fmt.Errorf("%w: %d bytes, need %d", ErrInvalidResponse, len(b), binary.Size(resp))
	}

	if err := binary.Read(bytes.NewReader(b), binary.LittleEndian, &resp); err != nil {
		return 0, fmt.Errorf("%w: %w", ErrInvalidResponse, err)
	}

	h := resp.Header
	if h.group() != GroupIDFWCaps || h.command() != CommandGetRule || !h.isResponse() {
		return 0, fmt.Errorf("%w: unexpected header 0x%08x", ErrInvalidResponse, uint32(h))
	}

	if h.result() != 0 {
		return 0, fmt.Errorf("%w: result 0x%02x", ErrCommandFailed, h.result())
	}

	if resp.RuleID != RuleIDFWCapsSKU || resp.RuleDataLen < 4 {
		return 0, fmt.Errorf("%w: rule 0x%x with %d data bytes", ErrInvalidResponse, resp.RuleID, resp.RuleDataLen)
	}

	return FWCapabilities(resp.RuleData), nil
}
