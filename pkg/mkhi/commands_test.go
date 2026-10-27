/*********************************************************************
 * Copyright (c) Intel Corporation 2026
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/

package mkhi

import (
	"encoding/binary"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type mockHECI struct {
	initErr  error
	response []byte
	sent     []byte
	closed   bool
}

func (m *mockHECI) Init(bool, bool) error  { return nil }
func (m *mockHECI) InitWithGUID(any) error { return m.initErr }
func (m *mockHECI) InitHOTHAM() error      { return nil }
func (m *mockHECI) GetBufferSize() uint32  { return 512 }
func (m *mockHECI) Close()                 { m.closed = true }
func (m *mockHECI) SendMessage(b []byte, _ *uint32) (int, error) {
	m.sent = append([]byte(nil), b...)

	return len(b), nil
}

func (m *mockHECI) ReceiveMessage(b []byte, done *uint32) (int, error) {
	n := copy(b, m.response)
	*done = uint32(n)

	return n, nil
}

// ruleResponse builds a FWCAPS_GET_RULE_ACK: header (group 3, command 2,
// is_response, result), rule ID, data length and 4-byte rule data.
func ruleResponse(result uint8, ruleID, data uint32) []byte {
	h := uint32(GroupIDFWCaps) | uint32(CommandGetRule)<<8 | 1<<15 | uint32(result)<<24

	b := binary.LittleEndian.AppendUint32(nil, h)
	b = binary.LittleEndian.AppendUint32(b, ruleID)
	b = append(b, 4)

	return binary.LittleEndian.AppendUint32(b, data)
}

func TestGetFWCapabilities(t *testing.T) {
	// FW caps observed shape: AMT (bit 2) and TEP (bit 24) set.
	want := FWCapsAMT | FWCapsTEP
	m := &mockHECI{response: ruleResponse(0, RuleIDFWCapsSKU, uint32(want))}

	caps, err := (&Command{Heci: m}).GetFWCapabilities()
	require.NoError(t, err)
	assert.Equal(t, want, caps)
	assert.True(t, caps.Has(FWCapsTEP))
	assert.False(t, caps.Has(FWCapsKVM))
	assert.True(t, m.closed)

	// Request: header group 3, command 2 (0x00000203), rule ID 0.
	assert.Equal(t, []byte{0x03, 0x02, 0, 0, 0, 0, 0, 0}, m.sent)

	for name, tc := range map[string]struct {
		response []byte
		wantErr  error
	}{
		"firmware result":    {ruleResponse(0x89, RuleIDFWCapsSKU, 0), ErrCommandFailed},
		"short response":     {[]byte{0x03, 0x82, 0, 0}, ErrInvalidResponse},
		"wrong rule":         {ruleResponse(0, 5, 0), ErrInvalidResponse},
		"not a response":     {append([]byte{0x03, 0x02, 0, 0}, ruleResponse(0, 0, 0)[4:]...), ErrInvalidResponse},
		"wrong group header": {append([]byte{0x01, 0x82, 0, 0}, ruleResponse(0, 0, 0)[4:]...), ErrInvalidResponse},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := (&Command{Heci: &mockHECI{response: tc.response}}).GetFWCapabilities()
			require.ErrorIs(t, err, tc.wantErr)
		})
	}

	t.Run("MKHI client unavailable", func(t *testing.T) {
		_, err := (&Command{Heci: &mockHECI{initErr: errors.New("no device")}}).GetFWCapabilities()
		require.ErrorIs(t, err, ErrMKHINotSupported)
	})
}

func TestTEPSupported(t *testing.T) {
	assert.True(t, TEPSupported(21, FWCapsTEP))
	assert.True(t, TEPSupported(18, FWCapsTEP|FWCapsAMT))
	assert.False(t, TEPSupported(21, FWCapsAMT), "bit 24 not set")
	assert.False(t, TEPSupported(16, FWCapsTEP), "bit 24 is Wireless Display before CSME 18")
}
