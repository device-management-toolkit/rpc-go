/*********************************************************************
 * Copyright (c) Intel Corporation 2026
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/

package upid

import (
	"encoding/binary"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func respondWith(response []byte) func(buffer []byte, done *uint32) (int, error) {
	return func(buffer []byte, done *uint32) (int, error) {
		n := copy(buffer, response)
		*done = uint32(n)

		return n, nil
	}
}

func TestCall(t *testing.T) {
	request := PlatformIDGetRequest{
		Header: UPIDHECIHeader{Feature: CommandFeaturePlatformID, Command: CommandPlatformIDGet},
	}

	tests := []struct {
		name      string
		setupMock func(*MockHECI)
		want      []byte
		wantErr   error
	}{
		{
			name: "returns only the bytes read",
			setupMock: func(m *MockHECI) {
				m.receiveMessageFunc = respondWith([]byte{0, CommandPlatformIDGet, 0, 0, 1, 0, 0, 0})
			},
			want: []byte{0, CommandPlatformIDGet, 0, 0, 1, 0, 0, 0},
		},
		{
			name: "send failure",
			setupMock: func(m *MockHECI) {
				m.sendMessageFunc = func([]byte, *uint32) (int, error) { return 0, errors.New("boom") }
			},
			wantErr: ErrCommandFailed,
		},
		{
			name: "incomplete send",
			setupMock: func(m *MockHECI) {
				m.sendMessageFunc = func([]byte, *uint32) (int, error) { return 1, nil }
			},
			wantErr: ErrCommandFailed,
		},
		{
			name: "receive failure",
			setupMock: func(m *MockHECI) {
				m.receiveMessageFunc = func([]byte, *uint32) (int, error) { return 0, errors.New("boom") }
			},
			wantErr: ErrCommandFailed,
		},
		{
			name:      "empty response",
			setupMock: func(*MockHECI) {},
			wantErr:   ErrInvalidResponse,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			var sent []byte

			m := &MockHECI{}
			m.sendMessageFunc = func(buffer []byte, _ *uint32) (int, error) {
				sent = append([]byte(nil), buffer...)

				return len(buffer), nil
			}
			tt.setupMock(m)

			cmd := &Command{Heci: m}

			got, err := cmd.call(&request)
			if tt.wantErr != nil {
				require.ErrorIs(t, err, tt.wantErr)

				return
			}

			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
			assert.Equal(t, []byte{CommandFeaturePlatformID, CommandPlatformIDGet, 0, 0}, sent)
		})
	}
}

func TestParseResponseHeader(t *testing.T) {
	response := make([]byte, minResponseSize)
	response[1] = CommandPlatformIDGet
	binary.LittleEndian.PutUint32(response[headerSize:], uint32(StatusInvalidState))

	t.Run("returns status", func(t *testing.T) {
		status, err := parseResponseHeader(response, CommandFeaturePlatformID, CommandPlatformIDGet)
		require.NoError(t, err)
		assert.Equal(t, uint32(StatusInvalidState), status)
	})

	t.Run("too short", func(t *testing.T) {
		_, err := parseResponseHeader(response[:minResponseSize-1], CommandFeaturePlatformID, CommandPlatformIDGet)
		require.ErrorIs(t, err, ErrInvalidResponse)
	})

	t.Run("wrong command", func(t *testing.T) {
		_, err := parseResponseHeader(response, CommandFeaturePlatformID, CommandFeatureStateSet)
		require.ErrorIs(t, err, ErrInvalidResponse)
	})

	t.Run("wrong feature", func(t *testing.T) {
		_, err := parseResponseHeader(response, CommandFeatureTEP, CommandPlatformIDGet)
		require.ErrorIs(t, err, ErrInvalidResponse)
	})
}
