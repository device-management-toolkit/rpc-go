/*********************************************************************
 * Copyright (c) Intel Corporation 2026
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/

package upid

import "fmt"

// String returns a hex-encoded string representation of the UPID with labels
func (u *UPID) String() string {
	if u == nil || u.Raw == nil {
		return ""
	}

	// Build CSME ID string (bytes 32-63)
	csmeID := ""
	for i := OEMPlatformIDSize; i < len(u.Raw); i++ {
		csmeID += hexChar(u.Raw[i]>>4) + hexChar(u.Raw[i]&0x0F)
	}

	return "---UPID---\nOEM_PLATFORM_ID_TYPE    : " + u.getPlatformIdTypeString() +
		"\nOEM ID                  : " + u.OEMID() +
		"\nCSME ID                 : " + csmeID
}

// OEMIDNotSet is reported as the OEM ID of a platform that has none: its
// type is "Not Set" or the ID is all zeros. Text output, JSON output and the
// Console sync all use it, as rpc-go 2.x does.
const OEMIDNotSet = "Not Set"

// OEMID returns the OEM platform ID as uppercase hex, or OEMIDNotSet when the
// platform has none.
func (u *UPID) OEMID() string {
	if u == nil {
		return ""
	}

	oem := u.OEMPlatformID
	if len(oem) == 0 && len(u.Raw) >= OEMPlatformIDSize {
		oem = u.Raw[:OEMPlatformIDSize]
	}

	if u.PlatformIdType == PlatformIDTypeNotSet {
		return OEMIDNotSet
	}

	for _, b := range oem {
		if b != 0 {
			return fmt.Sprintf("%X", oem)
		}
	}

	return OEMIDNotSet
}

// MarshalJSON implements custom JSON marshaling for UPID
// Returns a structured object with oemId, csmeId, and optionally oemPlatformIdType fields
func (u *UPID) MarshalJSON() ([]byte, error) {
	if u == nil || u.Raw == nil {
		return []byte(`{}`), nil
	}

	// Build CSME ID string (bytes 32-63)
	csmeID := ""
	for i := OEMPlatformIDSize; i < len(u.Raw); i++ {
		csmeID += hexChar(u.Raw[i]>>4) + hexChar(u.Raw[i]&0x0F)
	}

	return []byte(`{"oemPlatformIdType":"` + u.getPlatformIdTypeString() + `","oemId":"` + u.OEMID() + `","csmeId":"` + csmeID + `"}`), nil
}

// getPlatformIdTypeString converts the platform ID type to a human-readable string
func (u *UPID) getPlatformIdTypeString() string {
	switch u.PlatformIdType {
	case PlatformIDTypeNotSet:
		return "Not Set (0)"
	case PlatformIDTypeBinary:
		return "Binary (1)"
	case PlatformIDTypePrintableString:
		return "Printable String (2)"
	default:
		return fmt.Sprintf("Unknown (%d)", u.PlatformIdType)
	}
}

func hexChar(n byte) string {
	if n < 10 {
		return string(rune('0' + n))
	}

	return string(rune('A' + n - 10))
}
