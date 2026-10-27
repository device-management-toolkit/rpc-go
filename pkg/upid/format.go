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

	// Check if OEM Platform ID is all zeros (not provisioned)
	oemAllZeros := true

	for i := 0; i < OEMPlatformIDSize; i++ {
		if u.Raw[i] != 0 {
			oemAllZeros = false

			break
		}
	}

	// Build CSME ID string (bytes 32-63)
	csmeID := ""
	for i := OEMPlatformIDSize; i < len(u.Raw); i++ {
		csmeID += hexChar(u.Raw[i]>>4) + hexChar(u.Raw[i]&0x0F)
	}

	// Get platform ID type string
	platformTypeStr := u.getPlatformIdTypeString()

	// Build result starting with header
	result := "---UPID---\nOEM_PLATFORM_ID_TYPE    : " + platformTypeStr

	// If OEM Platform ID is not provisioned, show empty OEM ID
	if oemAllZeros {
		result += "\nOEM ID                  :\nCSME ID                 : " + csmeID

		return result
	}

	// Build OEM ID string (bytes 0-31)
	oemID := ""
	for i := 0; i < OEMPlatformIDSize; i++ {
		oemID += hexChar(u.Raw[i]>>4) + hexChar(u.Raw[i]&0x0F)
	}

	// Show both OEM and CSME IDs
	result += "\nOEM ID                  : " + oemID + "\nCSME ID                 : " + csmeID

	return result
}

// MarshalJSON implements custom JSON marshaling for UPID
// Returns a structured object with oemId, csmeId, and optionally oemPlatformIdType fields
func (u *UPID) MarshalJSON() ([]byte, error) {
	if u == nil || u.Raw == nil {
		return []byte(`{}`), nil
	}

	// Check if OEM Platform ID is all zeros (not provisioned)
	oemAllZeros := true

	for i := 0; i < OEMPlatformIDSize; i++ {
		if u.Raw[i] != 0 {
			oemAllZeros = false

			break
		}
	}

	// Build CSME ID string (bytes 32-63)
	csmeID := ""
	for i := OEMPlatformIDSize; i < len(u.Raw); i++ {
		csmeID += hexChar(u.Raw[i]>>4) + hexChar(u.Raw[i]&0x0F)
	}

	// Get platform ID type string
	platformIdTypeStr := u.getPlatformIdTypeString()

	// If OEM Platform ID is not provisioned, include empty oemId with type
	if oemAllZeros {
		return []byte(`{"oemPlatformIdType":"` + platformIdTypeStr + `","oemId":"","csmeId":"` + csmeID + `"}`), nil
	}

	// Build OEM ID string (bytes 0-31)
	oemID := ""
	for i := 0; i < OEMPlatformIDSize; i++ {
		oemID += hexChar(u.Raw[i]>>4) + hexChar(u.Raw[i]&0x0F)
	}

	// Return oemPlatformIdType, oemId, and csmeId
	return []byte(`{"oemPlatformIdType":"` + platformIdTypeStr + `","oemId":"` + oemID + `","csmeId":"` + csmeID + `"}`), nil
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
