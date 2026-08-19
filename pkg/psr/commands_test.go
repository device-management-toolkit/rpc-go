/*********************************************************************
 * Copyright (c) Intel Corporation 2026
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/

package psr

import (
	"encoding/binary"
	"errors"
	"testing"

	"github.com/device-management-toolkit/rpc-go/v2/pkg/heci"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// MockHECI is a hand-rolled heci.Interface stub, mirroring the one in
// pkg/upid so the two packages stay comparable.
type MockHECI struct {
	initWithGUIDFunc   func(guid interface{}) error
	sendMessageFunc    func(buffer []byte, done *uint32) (int, error)
	receiveMessageFunc func(buffer []byte, done *uint32) (int, error)
	bufferSize         uint32
	closed             bool
}

func (m *MockHECI) Init(useLME, useWD bool) error { return nil }

func (m *MockHECI) InitWithGUID(guid interface{}) error {
	if m.initWithGUIDFunc != nil {
		return m.initWithGUIDFunc(guid)
	}

	return nil
}

func (m *MockHECI) InitHOTHAM() error { return nil }

func (m *MockHECI) GetBufferSize() uint32 {
	if m.bufferSize != 0 {
		return m.bufferSize
	}

	return 5120
}

func (m *MockHECI) SendMessage(buffer []byte, done *uint32) (int, error) {
	if m.sendMessageFunc != nil {
		return m.sendMessageFunc(buffer, done)
	}

	return len(buffer), nil
}

func (m *MockHECI) ReceiveMessage(buffer []byte, done *uint32) (int, error) {
	if m.receiveMessageFunc != nil {
		return m.receiveMessageFunc(buffer, done)
	}

	return 0, nil
}

func (m *MockHECI) Close() { m.closed = true }

// buildResponse assembles a well-formed PSR response frame.
func buildResponse(command, status uint32, payload []byte) []byte {
	response := make([]byte, HeaderSize+StatusSize+len(payload))
	binary.LittleEndian.PutUint32(response[0:4], command)
	binary.LittleEndian.PutUint32(response[4:8], 0)
	binary.LittleEndian.PutUint32(response[8:12], uint32(StatusSize+len(payload)))
	binary.LittleEndian.PutUint32(response[HeaderSize:MinResponseSize], status)
	copy(response[MinResponseSize:], payload)

	return response
}

// replyWith returns a ReceiveMessage stub that hands back frame in fixed-size
// chunks, so the chunked-read path is exercised.
func replyWith(frame []byte, chunkSize int) func([]byte, *uint32) (int, error) {
	offset := 0

	return func(buffer []byte, done *uint32) (int, error) {
		if offset >= len(frame) {
			return 0, heci.ErrReadTimeout
		}

		end := offset + chunkSize
		if end > len(frame) {
			end = len(frame)
		}

		n := copy(buffer, frame[offset:end])
		offset += n

		return n, nil
	}
}

func TestNewNonce(t *testing.T) {
	first, err := newNonce()
	require.NoError(t, err)

	second, err := newNonce()
	require.NoError(t, err)

	assert.Len(t, first[:], NonceSize)
	assert.NotEqual(t, first, second, "nonce must not repeat across calls")
	assert.NotEqual(t, [NonceSize]byte{}, first, "nonce must not be all zero")
}

func TestGetPSRWithoutConfiguredGUID(t *testing.T) {
	// The PSR client GUID is a documented placeholder in this skeleton, so
	// retrieval must fail fast and explicitly rather than dialing a bogus
	// MEI client.
	if guidConfigured() {
		t.Skip("PSR GUID is configured; placeholder guard no longer applies")
	}

	cmd := &Command{Heci: &MockHECI{}}

	psr, err := cmd.GetPSR()
	assert.Nil(t, psr)
	assert.ErrorIs(t, err, ErrPSRGUIDNotConfigured)
}

func TestGetRecord(t *testing.T) {
	payload := []byte{0xAA, 0xBB, 0xCC, 0xDD}

	tests := []struct {
		name      string
		setupMock func(*MockHECI)
		wantErr   error
		check     func(*testing.T, *PSR)
	}{
		{
			name: "successful retrieval in a single chunk",
			setupMock: func(m *MockHECI) {
				m.receiveMessageFunc = replyWith(buildResponse(CommandGetPlatformServiceRecord, StatusSuccess, payload), 4096)
			},
			check: func(t *testing.T, psr *PSR) {
				assert.Equal(t, StatusSuccess, psr.Status)
				assert.Equal(t, payload, psr.Payload)
				assert.Len(t, psr.UserNonce, NonceSize)
			},
		},
		{
			name: "response spanning multiple chunks is reassembled",
			setupMock: func(m *MockHECI) {
				m.bufferSize = 8
				m.receiveMessageFunc = replyWith(buildResponse(CommandGetPlatformServiceRecord, StatusSuccess, payload), 8)
			},
			check: func(t *testing.T, psr *PSR) {
				assert.Equal(t, payload, psr.Payload)
			},
		},
		{
			name: "non-success status is surfaced as an error",
			setupMock: func(m *MockHECI) {
				m.receiveMessageFunc = replyWith(buildResponse(CommandGetPlatformServiceRecord, 0x0B, nil), 4096)
			},
			wantErr: ErrCommandFailed,
		},
		{
			name: "unexpected command in response is rejected",
			setupMock: func(m *MockHECI) {
				m.receiveMessageFunc = replyWith(buildResponse(CommandGetPlatformServiceRecord+1, StatusSuccess, nil), 4096)
			},
			wantErr: ErrInvalidResponse,
		},
		{
			name: "truncated response is rejected",
			setupMock: func(m *MockHECI) {
				m.receiveMessageFunc = replyWith([]byte{0x01, 0x02}, 4096)
			},
			wantErr: ErrInvalidResponse,
		},
		{
			name: "empty response is rejected",
			setupMock: func(m *MockHECI) {
				m.receiveMessageFunc = func(buffer []byte, done *uint32) (int, error) { return 0, nil }
			},
			wantErr: ErrInvalidResponse,
		},
		{
			name: "send failure is surfaced",
			setupMock: func(m *MockHECI) {
				m.sendMessageFunc = func(buffer []byte, done *uint32) (int, error) {
					return 0, errors.New("mei write failed")
				}
			},
			wantErr: ErrCommandFailed,
		},
		{
			name: "short write is surfaced",
			setupMock: func(m *MockHECI) {
				m.sendMessageFunc = func(buffer []byte, done *uint32) (int, error) {
					return len(buffer) - 1, nil
				}
			},
			wantErr: ErrCommandFailed,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			mock := &MockHECI{}
			tt.setupMock(mock)

			cmd := &Command{Heci: mock}

			psr, err := cmd.getRecord([NonceSize]byte{})
			if tt.wantErr != nil {
				assert.ErrorIs(t, err, tt.wantErr)
				assert.Nil(t, psr)

				return
			}

			require.NoError(t, err)
			require.NotNil(t, psr)
			tt.check(t, psr)
		})
	}
}

func TestSendSerializesNonce(t *testing.T) {
	var sent []byte

	mock := &MockHECI{
		sendMessageFunc: func(buffer []byte, done *uint32) (int, error) {
			sent = append([]byte(nil), buffer...)

			return len(buffer), nil
		},
		receiveMessageFunc: replyWith(buildResponse(CommandGetPlatformServiceRecord, StatusSuccess, nil), 4096),
	}

	nonce := [NonceSize]byte{1, 2, 3, 4, 5}
	cmd := &Command{Heci: mock}

	_, err := cmd.getRecord(nonce)
	require.NoError(t, err)

	require.Len(t, sent, HeaderSize+NonceSize)
	assert.Equal(t, CommandGetPlatformServiceRecord, binary.LittleEndian.Uint32(sent[0:4]))
	assert.Equal(t, uint32(NonceSize), binary.LittleEndian.Uint32(sent[8:12]))
	assert.Equal(t, nonce[:], sent[HeaderSize:])
}

func TestResponseComplete(t *testing.T) {
	frame := buildResponse(CommandGetPlatformServiceRecord, StatusSuccess, []byte{1, 2, 3, 4})

	partialHeader, err := responseComplete(frame[:HeaderSize-1])
	require.NoError(t, err)
	assert.False(t, partialHeader, "an incomplete header cannot be complete")

	partialBody, err := responseComplete(frame[:len(frame)-1])
	require.NoError(t, err)
	assert.False(t, partialBody)

	full, err := responseComplete(frame)
	require.NoError(t, err)
	assert.True(t, full)
}

func TestCloseReleasesHECI(t *testing.T) {
	mock := &MockHECI{}
	cmd := &Command{Heci: mock}

	cmd.Close()
	assert.True(t, mock.closed)

	// A nil HECI must not panic.
	assert.NotPanics(t, func() { (&Command{}).Close() })
}

func TestUnimplementedExtensionPoints(t *testing.T) {
	psr := &PSR{}

	assert.ErrorIs(t, psr.ParseRecord(), ErrRecordParsingNotImpl)
	assert.ErrorIs(t, psr.VerifySignature(), ErrSignatureVerifyNotImpl)
}
