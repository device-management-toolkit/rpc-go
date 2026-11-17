/*********************************************************************
 * Copyright (c) Intel Corporation 2026
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/

package heci

import (
	"encoding/hex"
	"fmt"
	"strings"
)

// meiGUIDFromString parses a client GUID written in registry form,
// "{D1-D2-D3-D4-D5}" (braces optional), into the 16-byte layout the MEI
// driver expects: Data1, Data2 and Data3 little-endian, followed by the eight
// Data4 bytes in order. It is the Linux counterpart of windows.GUIDFromString.
func meiGUIDFromString(guid string) ([16]byte, error) {
	var out [16]byte

	s := strings.TrimSuffix(strings.TrimPrefix(strings.TrimSpace(guid), "{"), "}")

	parts := strings.Split(s, "-")
	if len(parts) != 5 || len(parts[0]) != 8 || len(parts[1]) != 4 || len(parts[2]) != 4 || len(parts[3]) != 4 || len(parts[4]) != 12 {
		return out, fmt.Errorf("invalid GUID %q", guid)
	}

	raw, err := hex.DecodeString(strings.Join(parts, ""))
	if err != nil {
		return out, fmt.Errorf("invalid GUID %q: %w", guid, err)
	}

	out[0], out[1], out[2], out[3] = raw[3], raw[2], raw[1], raw[0]
	out[4], out[5] = raw[5], raw[4]
	out[6], out[7] = raw[7], raw[6]
	copy(out[8:], raw[8:])

	return out, nil
}
