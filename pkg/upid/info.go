/*********************************************************************
 * Copyright (c) Intel Corporation 2026
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/

package upid

import "fmt"

// OEMIDNotSet is reported as the OEM ID of a platform that has none: its
// type is "Not Set" or the ID is all zeros.
const OEMIDNotSet = "Not Set"

// Info is the UPID in the shape Console stores in deviceInfo.upid: uppercase
// hex IDs plus a human-readable OEM platform ID type. It matches the payload
// v3 `rpc amtinfo --sync` sends to Console (syncUPIDInfo).
type Info struct {
	CSMEId            string `json:"csmeId,omitempty"`
	OEMId             string `json:"oemId,omitempty"`
	OEMPlatformIdType string `json:"oemPlatformIdType,omitempty"`
}

// Info converts the UPID to its reported form. A nil UPID yields nil.
func (u *UPID) Info() *Info {
	if u == nil {
		return nil
	}

	return &Info{
		CSMEId:            formatHex(u.HWSerialNum),
		OEMId:             u.oemID(),
		OEMPlatformIdType: platformIDTypeString(u.PlatformIdType),
	}
}

// oemID renders the OEM platform ID, or OEMIDNotSet when the platform has none.
func (u *UPID) oemID() string {
	if u.PlatformIdType == PlatformIDTypeNotSet {
		return OEMIDNotSet
	}

	for _, b := range u.OEMPlatformID {
		if b != 0 {
			return formatHex(u.OEMPlatformID)
		}
	}

	return OEMIDNotSet
}

// formatHex renders b as uppercase hex, or "" when empty.
func formatHex(b []byte) string {
	if len(b) == 0 {
		return ""
	}

	return fmt.Sprintf("%X", b)
}

// platformIDTypeString maps the UPID platform ID type enum to a human-readable string.
func platformIDTypeString(t uint32) string {
	switch t {
	case PlatformIDTypeNotSet:
		return "Not Set (0)"
	case PlatformIDTypeBinary:
		return "Binary (1)"
	case PlatformIDTypePrintableString:
		return "Printable String (2)"
	default:
		return fmt.Sprintf("Unknown (%d)", t)
	}
}
