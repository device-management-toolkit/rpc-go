/*********************************************************************
 * Copyright (c) Intel Corporation 2026
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/

package local

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"testing"

	"github.com/device-management-toolkit/rpc-go/v2/internal/flags"
	"github.com/device-management-toolkit/rpc-go/v2/pkg/upid"
	"github.com/device-management-toolkit/rpc-go/v2/pkg/utils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type mockUPIDCommand struct {
	upid *upid.UPID
	err  error
}

func (m mockUPIDCommand) GetUPID() (*upid.UPID, error) { return m.upid, m.err }

// captureStdout returns everything fn writes to os.Stdout.
func captureStdout(t *testing.T, fn func()) string {
	t.Helper()

	orig := os.Stdout

	r, w, err := os.Pipe()
	require.NoError(t, err)

	os.Stdout = w

	done := make(chan string)

	go func() {
		var buf bytes.Buffer

		_, _ = io.Copy(&buf, r)
		done <- buf.String()
	}()

	defer func() { os.Stdout = orig }()

	fn()

	require.NoError(t, w.Close())

	return <-done
}

func testUPID(t *testing.T) *upid.UPID {
	t.Helper()

	raw := make([]byte, upid.UPIDSize)
	for i := range raw {
		raw[i] = byte(i)
	}

	platformID, err := upid.NewUPID(raw, upid.PlatformIDTypeBinary)
	require.NoError(t, err)

	return platformID
}

func TestDisplayAMTInfoIdentifiers(t *testing.T) {
	const serial = "PF1ABC23"

	identifierFlags := flags.AmtInfoFlags{UUID: true, SerialNumber: true, UPID: true}
	platformID := testUPID(t)
	wantUPID := platformID.Info()

	serialOK := func() (string, error) { return serial, nil }
	serialMissing := func() (string, error) { return "", utils.ErrSerialNumberUnavailable }
	serialBlank := func() (string, error) { return "", nil }

	tests := map[string]struct {
		upidCommand  upid.Interface
		serialNumber func() (string, error)
		wantSerial   bool
		wantUPID     bool
		// wantUPIDText is the text-mode UPID line when the UPID is unavailable.
		wantUPIDText string
	}{
		"all identifiers available": {
			upidCommand:  mockUPIDCommand{upid: platformID},
			serialNumber: serialOK,
			wantSerial:   true,
			wantUPID:     true,
		},
		"UPID unsupported still returns UUID and serial number": {
			upidCommand:  mockUPIDCommand{err: fmt.Errorf("%w: The handle is invalid.", upid.ErrUPIDNotSupported)},
			serialNumber: serialOK,
			wantSerial:   true,
			wantUPIDText: "UPID			: Not Supported\n",
		},
		"UPID returns nothing without error": {
			upidCommand:  mockUPIDCommand{},
			serialNumber: serialOK,
			wantSerial:   true,
			wantUPIDText: "UPID			: Not Available",
		},
		"serial number unavailable still returns UUID and UPID": {
			upidCommand:  mockUPIDCommand{upid: platformID},
			serialNumber: serialMissing,
			wantUPID:     true,
		},
		"blank serial number is omitted": {
			upidCommand:  mockUPIDCommand{upid: platformID},
			serialNumber: serialBlank,
			wantUPID:     true,
		},
		"serial number and UPID unavailable still returns UUID": {
			upidCommand:  mockUPIDCommand{err: upid.ErrConnectionFailed},
			serialNumber: serialMissing,
			wantUPIDText: "UPID			: Not Available (" + upid.ErrConnectionFailed.Error() + ")",
		},
		"no identifier sources configured": {},
	}

	for name, tc := range tests {
		t.Run(name+" (json)", func(t *testing.T) {
			f := flags.NewFlags(nil, MockPRSuccess)
			f.AmtInfo = identifierFlags
			f.JsonOutput = true

			lps := setupService(f)
			lps.upidCommand = tc.upidCommand
			lps.serialNumber = tc.serialNumber

			var err error

			out := captureStdout(t, func() { err = lps.DisplayAMTInfo() })
			require.NoError(t, err)

			var got struct {
				UUID         *string    `json:"uuid"`
				SerialNumber *string    `json:"serialNumber"`
				UPID         *upid.Info `json:"upid"`
			}

			require.NoError(t, json.Unmarshal([]byte(out), &got), out)
			require.NotNil(t, got.UUID, "uuid must always be reported")

			// A struct cannot tell a missing key from a null one, so the
			// omitted identifiers are checked on the raw keys.
			var keys map[string]json.RawMessage

			require.NoError(t, json.Unmarshal([]byte(out), &keys), out)

			if tc.wantSerial {
				require.NotNil(t, got.SerialNumber)
				assert.Equal(t, serial, *got.SerialNumber)
			} else {
				assert.NotContains(t, keys, "serialNumber")
			}

			if tc.wantUPID {
				assert.Equal(t, wantUPID, got.UPID)
			} else {
				assert.NotContains(t, keys, "upid")
			}
		})

		t.Run(name+" (text)", func(t *testing.T) {
			f := flags.NewFlags(nil, MockPRSuccess)
			f.AmtInfo = identifierFlags

			lps := setupService(f)
			lps.upidCommand = tc.upidCommand
			lps.serialNumber = tc.serialNumber

			var err error

			out := captureStdout(t, func() { err = lps.DisplayAMTInfo() })
			require.NoError(t, err)

			assert.Contains(t, out, "UUID")

			if tc.wantSerial {
				assert.Contains(t, out, "Serial Number		: "+serial)
			} else if tc.serialNumber != nil {
				assert.Contains(t, out, "Serial Number		: Not Available")
			} else {
				assert.NotContains(t, out, "Serial Number")
			}

			if tc.wantUPID {
				assert.Contains(t, out, "UPID CSME ID		: "+wantUPID.CSMEId)
				assert.Contains(t, out, "UPID OEM ID		: "+wantUPID.OEMId)
				assert.Contains(t, out, "UPID OEM ID Type	: "+wantUPID.OEMPlatformIdType)
			} else {
				assert.NotContains(t, out, "UPID CSME ID")

				if tc.wantUPIDText != "" {
					assert.Contains(t, out, tc.wantUPIDText)
				} else {
					assert.NotContains(t, out, "UPID")
				}
			}
		})
	}

	t.Run("OEM ID of type Not Set is reported as Not Set", func(t *testing.T) {
		notSet, err := upid.NewUPID(make([]byte, upid.UPIDSize), upid.PlatformIDTypeNotSet)
		require.NoError(t, err)

		for _, jsonOutput := range []bool{false, true} {
			f := flags.NewFlags(nil, MockPRSuccess)
			f.AmtInfo = flags.AmtInfoFlags{UPID: true}
			f.JsonOutput = jsonOutput

			lps := setupService(f)
			lps.upidCommand = mockUPIDCommand{upid: notSet}

			out := captureStdout(t, func() { err = lps.DisplayAMTInfo() })
			require.NoError(t, err)

			if jsonOutput {
				var got struct {
					UPID upid.Info `json:"upid"`
				}

				require.NoError(t, json.Unmarshal([]byte(out), &got), out)
				assert.Equal(t, upid.OEMIDNotSet, got.UPID.OEMId)
				assert.Equal(t, "Not Set (0)", got.UPID.OEMPlatformIdType)
			} else {
				assert.Contains(t, out, "UPID OEM ID		: Not Set\n")
				assert.Contains(t, out, "UPID OEM ID Type	: Not Set (0)")
			}
		}
	})

	t.Run("identifiers are not read unless requested", func(t *testing.T) {
		f := flags.NewFlags(nil, MockPRSuccess)
		f.AmtInfo = flags.AmtInfoFlags{UUID: true}
		f.JsonOutput = true

		lps := setupService(f)
		lps.upidCommand = mockUPIDCommand{upid: platformID}
		lps.serialNumber = serialOK

		var err error

		out := captureStdout(t, func() { err = lps.DisplayAMTInfo() })
		require.NoError(t, err)
		assert.NotContains(t, out, "serialNumber")
		assert.NotContains(t, out, "upid")
	})
}
