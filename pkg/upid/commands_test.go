/*********************************************************************
 * Copyright (c) Intel Corporation 2026
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/

package upid

import (
	"encoding/binary"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/device-management-toolkit/rpc-go/v2/pkg/heci"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewUPID(t *testing.T) {
	tests := []struct {
		name    string
		input   []byte
		wantErr bool
	}{
		{name: "Valid UPID", input: make([]byte, UPIDSize)},
		{name: "Invalid size - too short", input: make([]byte, 32), wantErr: true},
		{name: "Invalid size - too long", input: make([]byte, 128), wantErr: true},
		{name: "Empty input", input: []byte{}, wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			u, err := NewUPID(tt.input, PlatformIDTypeBinary)
			if tt.wantErr {
				assert.Error(t, err)
				assert.Nil(t, u)

				return
			}

			require.NoError(t, err)
			require.NotNil(t, u)
			assert.Len(t, u.Raw, UPIDSize)
			assert.Len(t, u.OEMPlatformID, OEMPlatformIDSize)
			assert.Len(t, u.HWSerialNum, HWSerialNumSize)
			assert.Equal(t, PlatformIDTypeBinary, u.PlatformIdType)
		})
	}
}

func TestNewUPIDSplitsHalves(t *testing.T) {
	raw := make([]byte, UPIDSize)
	for i := 0; i < OEMPlatformIDSize; i++ {
		raw[i] = 0xAA
	}

	for i := OEMPlatformIDSize; i < UPIDSize; i++ {
		raw[i] = 0xBB
	}

	u, err := NewUPID(raw, PlatformIDTypeBinary)
	require.NoError(t, err)

	for i := 0; i < OEMPlatformIDSize; i++ {
		assert.Equal(t, byte(0xAA), u.OEMPlatformID[i])
		assert.Equal(t, byte(0xBB), u.HWSerialNum[i])
	}
}

func TestCommandConstants(t *testing.T) {
	assert.Equal(t, uint8(0), CommandFeaturePlatformID)
	assert.Equal(t, uint8(0), CommandFeatureSupportGet)
	assert.Equal(t, uint8(1), CommandFeatureStateGet)
	assert.Equal(t, uint8(2), CommandFeatureStateSet)
	assert.Equal(t, uint8(3), CommandFeatureStateOSControlGet)
	assert.Equal(t, uint8(4), CommandFeatureStateOSControlSet)
	assert.Equal(t, uint8(5), CommandPlatformIDGet)
	assert.Equal(t, uint8(6), CommandRefurbishCounterGet)
	assert.Equal(t, uint8(7), CommandOEMPlatformIDUpdate)
}

func TestStatusConstants(t *testing.T) {
	assert.Equal(t, uint32(0), StatusSuccess)
	assert.Equal(t, uint32(1), StatusFeatureNotSupported)
	assert.Equal(t, uint32(2), StatusInvalidInputParameter)
	assert.Equal(t, uint32(3), StatusInternalError)
	assert.Equal(t, uint32(4), StatusNotAllowedAfterEOP)
	assert.Equal(t, uint32(5), StatusNotAllowedAfterManufLock)
	assert.Equal(t, uint32(6), StatusMaxCountersExceeded)
	assert.Equal(t, uint32(7), StatusInvalidState)
	assert.Equal(t, uint32(8), StatusReserved2)
	assert.Equal(t, uint32(9), StatusNotAllowedAfterCBD)
}

func TestFeatureStateAndPlatformIDTypeConstants(t *testing.T) {
	assert.Equal(t, uint8(0), FeatureStateDisabled)
	assert.Equal(t, uint8(1), FeatureStateEnabled)
	assert.Equal(t, uint32(0), PlatformIDTypeNotSet)
	assert.Equal(t, uint32(1), PlatformIDTypeBinary)
	assert.Equal(t, uint32(2), PlatformIDTypePrintableString)
}

func TestErrorDefinitions(t *testing.T) {
	for _, err := range []error{
		ErrUPIDNotSupported, ErrUPIDNotEnabled, ErrUPIDNotProvisioned, ErrInvalidResponse,
		ErrConnectionFailed, ErrCommandFailed, ErrCommandTimeout, ErrInsufficientPriv,
		ErrFeatureNotSupported, ErrInvalidInputParameter, ErrInternalError, ErrNotAllowedAfterEOP,
		ErrInvalidState, ErrNotAllowedAfterManufLock, ErrMaxCountersExceeded, ErrNotAllowedAfterCBD,
	} {
		require.Error(t, err)
		assert.NotEmpty(t, err.Error())
	}
}

func TestMapStatusError(t *testing.T) {
	tests := []struct {
		status uint32
		want   error
	}{
		{StatusFeatureNotSupported, ErrFeatureNotSupported},
		{StatusInvalidInputParameter, ErrInvalidInputParameter},
		{StatusInternalError, ErrInternalError},
		{StatusNotAllowedAfterEOP, ErrNotAllowedAfterEOP},
		{StatusNotAllowedAfterManufLock, ErrNotAllowedAfterManufLock},
		{StatusMaxCountersExceeded, ErrMaxCountersExceeded},
		{StatusInvalidState, ErrInvalidState},
		{StatusNotAllowedAfterCBD, ErrNotAllowedAfterCBD},
	}

	for _, tt := range tests {
		assert.Equal(t, tt.want, mapStatusError(tt.status), "status %d", tt.status)
	}

	// Statuses outside the known set must not be folded onto a known error by
	// truncation: 0x101 is not "feature not supported" and 0x100 is not success.
	for _, status := range []uint32{0x100, 0x101, 0x1000000, StatusReserved2} {
		err := mapStatusError(status)
		assert.ErrorIs(t, err, ErrCommandFailed, "status 0x%x", status)
		assert.Contains(t, err.Error(), fmt.Sprintf("0x%08x", status))
	}
}

func TestNewCommand(t *testing.T) {
	cmd := NewCommand()
	require.NotNil(t, cmd)

	c, ok := cmd.(*Command)
	require.True(t, ok)
	assert.NotNil(t, c.Heci)
	assert.Equal(t, DefaultCommandTimeout, c.timeout())
}

// mockHECI is a scripted heci.Interface: it records the requests sent and
// answers each from responses keyed by command code.
type mockHECI struct {
	mu sync.Mutex

	initErr   error
	guid      string
	responses map[uint8]func(request []byte) ([]byte, error)
	// block, when non-nil, makes ReceiveMessage wait until it is closed.
	block chan struct{}

	sent       [][]byte
	closed     bool
	closeCount int
}

func (m *mockHECI) Init(useLME, useWD bool) error { return nil }

func (m *mockHECI) InitWithGUID(guid string) error {
	m.guid = guid

	return m.initErr
}

func (m *mockHECI) GetBufferSize() uint32 { return 5120 }

func (m *mockHECI) SendMessage(buffer []byte, done *uint32) (uint32, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.sent = append(m.sent, append([]byte(nil), buffer...))

	return uint32(len(buffer)), nil
}

func (m *mockHECI) ReceiveMessage(buffer []byte, done *uint32) (uint32, error) {
	if m.block != nil {
		<-m.block
	}

	m.mu.Lock()
	request := m.sent[len(m.sent)-1]
	m.mu.Unlock()

	handler, ok := m.responses[request[1]]
	if !ok {
		return 0, fmt.Errorf("unexpected UPID command %d", request[1])
	}

	response, err := handler(request)
	if err != nil {
		return 0, err
	}

	return uint32(copy(buffer, response)), nil
}

func (m *mockHECI) Close() { m.closed = true; m.closeCount++ }

// commands returns the command codes sent so far, in order.
func (m *mockHECI) commands() []uint8 {
	m.mu.Lock()
	defer m.mu.Unlock()

	out := make([]uint8, 0, len(m.sent))
	for _, request := range m.sent {
		out = append(out, request[1])
	}

	return out
}

// statusResponse builds a response with the given command, status and body.
func statusResponse(command uint8, status uint32, body ...byte) []byte {
	response := make([]byte, minResponseSize+len(body))
	response[0] = CommandFeaturePlatformID
	response[1] = command
	binary.LittleEndian.PutUint16(response[2:4], uint16(4+len(body)))
	binary.LittleEndian.PutUint32(response[4:8], status)
	copy(response[minResponseSize:], body)

	return response
}

// platformIDResponse builds a full successful PlatformIDGet response.
func platformIDResponse(idType uint32, oem, csme byte) []byte {
	body := make([]byte, 4+OEMPlatformIDSize+HWSerialNumSize)
	binary.LittleEndian.PutUint32(body[0:4], idType)

	for i := 4; i < 4+OEMPlatformIDSize; i++ {
		body[i] = oem
	}

	for i := 4 + OEMPlatformIDSize; i < len(body); i++ {
		body[i] = csme
	}

	return statusResponse(CommandPlatformIDGet, StatusSuccess, body...)
}

func respond(response []byte) func([]byte) ([]byte, error) {
	return func([]byte) ([]byte, error) { return response, nil }
}

// featureState returns a FEATURE_STATE_GET handler reporting enabled.
func featureState(enabled bool) func([]byte) ([]byte, error) {
	state := FeatureStateDisabled
	if enabled {
		state = FeatureStateEnabled
	}

	return respond(statusResponse(CommandFeatureStateGet, StatusSuccess, state))
}

// featureStateSet returns a FEATURE_STATE_SET handler that records each requested state in states.
func featureStateSet(states *[]uint8) func([]byte) ([]byte, error) {
	return func(request []byte) ([]byte, error) {
		*states = append(*states, request[headerSize])

		return statusResponse(CommandFeatureStateSet, StatusSuccess), nil
	}
}

func TestGetUPID(t *testing.T) {
	tests := []struct {
		name         string
		setup        func(*mockHECI, *[]uint8)
		wantErr      error
		wantCommands []uint8
		wantSets     []uint8
		checkUPID    func(*testing.T, *UPID)
	}{
		{
			name: "feature already enabled - read without toggling",
			setup: func(m *mockHECI, sets *[]uint8) {
				m.responses[CommandFeatureStateGet] = featureState(true)
				m.responses[CommandFeatureStateSet] = featureStateSet(sets)
				m.responses[CommandPlatformIDGet] = respond(platformIDResponse(PlatformIDTypeBinary, 0xAA, 0xBB))
			},
			wantCommands: []uint8{CommandFeatureStateGet, CommandPlatformIDGet},
			checkUPID: func(t *testing.T, u *UPID) {
				assert.Equal(t, PlatformIDTypeBinary, u.PlatformIdType)
				assert.Equal(t, byte(0xAA), u.OEMPlatformID[0])
				assert.Equal(t, byte(0xAA), u.OEMPlatformID[OEMPlatformIDSize-1])
				assert.Equal(t, byte(0xBB), u.HWSerialNum[0])
				assert.Equal(t, byte(0xBB), u.HWSerialNum[HWSerialNumSize-1])
			},
		},
		{
			name: "feature disabled - enable, read, disable again",
			setup: func(m *mockHECI, sets *[]uint8) {
				m.responses[CommandFeatureStateGet] = featureState(false)
				m.responses[CommandFeatureStateSet] = featureStateSet(sets)
				m.responses[CommandPlatformIDGet] = respond(platformIDResponse(PlatformIDTypePrintableString, 0x11, 0x22))
			},
			wantCommands: []uint8{CommandFeatureStateGet, CommandFeatureStateSet, CommandPlatformIDGet, CommandFeatureStateSet},
			wantSets:     []uint8{FeatureStateEnabled, FeatureStateDisabled},
			checkUPID: func(t *testing.T, u *UPID) {
				assert.Equal(t, PlatformIDTypePrintableString, u.PlatformIdType)
				assert.Equal(t, byte(0x22), u.HWSerialNum[0])
			},
		},
		{
			name: "read fails after enabling - still disables again",
			setup: func(m *mockHECI, sets *[]uint8) {
				m.responses[CommandFeatureStateGet] = featureState(false)
				m.responses[CommandFeatureStateSet] = featureStateSet(sets)
				m.responses[CommandPlatformIDGet] = respond(statusResponse(CommandPlatformIDGet, StatusInvalidState))
			},
			wantErr:      ErrInvalidState,
			wantCommands: []uint8{CommandFeatureStateGet, CommandFeatureStateSet, CommandPlatformIDGet, CommandFeatureStateSet},
			wantSets:     []uint8{FeatureStateEnabled, FeatureStateDisabled},
		},
		{
			name: "feature state unreadable - read without toggling",
			setup: func(m *mockHECI, sets *[]uint8) {
				m.responses[CommandFeatureStateGet] = respond(statusResponse(CommandFeatureStateGet, StatusFeatureNotSupported))
				m.responses[CommandFeatureStateSet] = featureStateSet(sets)
				m.responses[CommandPlatformIDGet] = respond(platformIDResponse(PlatformIDTypeNotSet, 0x00, 0xCC))
			},
			wantCommands: []uint8{CommandFeatureStateGet, CommandPlatformIDGet},
			checkUPID: func(t *testing.T, u *UPID) {
				assert.Equal(t, byte(0xCC), u.HWSerialNum[0])
			},
		},
		{
			name: "enable rejected - read as-is, nothing to disable",
			setup: func(m *mockHECI, sets *[]uint8) {
				m.responses[CommandFeatureStateGet] = featureState(false)
				m.responses[CommandFeatureStateSet] = respond(statusResponse(CommandFeatureStateSet, StatusNotAllowedAfterEOP))
				m.responses[CommandPlatformIDGet] = respond(statusResponse(CommandPlatformIDGet, StatusInvalidState))
			},
			wantErr:      ErrInvalidState,
			wantCommands: []uint8{CommandFeatureStateGet, CommandFeatureStateSet, CommandPlatformIDGet},
		},
		{
			name: "UPID not provisioned - short success response",
			setup: func(m *mockHECI, sets *[]uint8) {
				m.responses[CommandFeatureStateGet] = featureState(true)
				m.responses[CommandPlatformIDGet] = respond(statusResponse(CommandPlatformIDGet, StatusSuccess))
			},
			wantErr:      ErrUPIDNotProvisioned,
			wantCommands: []uint8{CommandFeatureStateGet, CommandPlatformIDGet},
		},
		{
			name: "unknown status is reported, not mapped",
			setup: func(m *mockHECI, sets *[]uint8) {
				m.responses[CommandFeatureStateGet] = featureState(true)
				m.responses[CommandPlatformIDGet] = respond(statusResponse(CommandPlatformIDGet, 0x101))
			},
			wantErr:      ErrCommandFailed,
			wantCommands: []uint8{CommandFeatureStateGet, CommandPlatformIDGet},
		},
		{
			name: "response for a different command is rejected",
			setup: func(m *mockHECI, sets *[]uint8) {
				m.responses[CommandFeatureStateGet] = featureState(true)
				m.responses[CommandPlatformIDGet] = respond(statusResponse(CommandFeatureStateGet, StatusSuccess))
			},
			wantErr: ErrInvalidResponse,
		},
		{
			name: "response for a different feature is rejected",
			setup: func(m *mockHECI, sets *[]uint8) {
				m.responses[CommandFeatureStateGet] = featureState(true)
				m.responses[CommandPlatformIDGet] = func([]byte) ([]byte, error) {
					response := platformIDResponse(PlatformIDTypeBinary, 0xAA, 0xBB)
					response[0] = 1

					return response, nil
				}
			},
			wantErr: ErrInvalidResponse,
		},
		{
			name: "truncated response is rejected",
			setup: func(m *mockHECI, sets *[]uint8) {
				m.responses[CommandFeatureStateGet] = featureState(true)
				m.responses[CommandPlatformIDGet] = respond([]byte{0, CommandPlatformIDGet, 0})
			},
			wantErr: ErrInvalidResponse,
		},
		{
			name: "empty response is rejected",
			setup: func(m *mockHECI, sets *[]uint8) {
				m.responses[CommandFeatureStateGet] = featureState(true)
				m.responses[CommandPlatformIDGet] = respond(nil)
			},
			wantErr: ErrInvalidResponse,
		},
		{
			name: "receive error",
			setup: func(m *mockHECI, sets *[]uint8) {
				m.responses[CommandFeatureStateGet] = featureState(true)
				m.responses[CommandPlatformIDGet] = func([]byte) ([]byte, error) { return nil, errors.New("no such device") }
			},
			wantErr: ErrCommandFailed,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var sets []uint8

			mock := &mockHECI{responses: map[uint8]func([]byte) ([]byte, error){}}
			tt.setup(mock, &sets)

			cmd := &Command{Heci: mock}

			u, err := cmd.GetUPID()

			if tt.wantErr != nil {
				assert.ErrorIs(t, err, tt.wantErr)
				assert.Nil(t, u)
			} else {
				require.NoError(t, err)
				require.NotNil(t, u)
				tt.checkUPID(t, u)
			}

			assert.Equal(t, UPIDGUID, mock.guid)
			assert.True(t, mock.closed, "HECI must be closed")

			if tt.wantCommands != nil {
				assert.Equal(t, tt.wantCommands, mock.commands())
			}

			assert.Equal(t, tt.wantSets, sets)
		})
	}
}

func TestGetUPIDNotSupported(t *testing.T) {
	driverErr := errors.New("the handle is invalid")
	mock := &mockHECI{initErr: fmt.Errorf("%w: %w", heci.ErrClientNotFound, driverErr)}
	cmd := &Command{Heci: mock}

	u, err := cmd.GetUPID()
	assert.ErrorIs(t, err, ErrUPIDNotSupported)
	assert.ErrorIs(t, err, driverErr, "the driver error must stay visible")
	assert.Nil(t, u)
	assert.Equal(t, UPIDGUID, mock.guid)
	assert.Empty(t, mock.commands(), "no command may be sent without a connected client")
}

// A driver or access failure is not "unsupported": the platform may well have
// a UPID that simply could not be reached.
func TestGetUPIDConnectionFailed(t *testing.T) {
	driverErr := errors.New("access is denied")
	mock := &mockHECI{initErr: driverErr}
	cmd := &Command{Heci: mock}

	u, err := cmd.GetUPID()
	assert.ErrorIs(t, err, ErrConnectionFailed)
	assert.ErrorIs(t, err, driverErr)
	assert.NotErrorIs(t, err, ErrUPIDNotSupported)
	assert.Nil(t, u)
	assert.Empty(t, mock.commands(), "no command may be sent without a connected client")
}

func TestGetUPIDTimesOutOnSilentClient(t *testing.T) {
	mock := &mockHECI{
		responses: map[uint8]func([]byte) ([]byte, error){},
		block:     make(chan struct{}),
	}

	t.Cleanup(func() { close(mock.block) })

	cmd := &Command{Heci: mock, Timeout: 20 * time.Millisecond}

	start := time.Now()
	u, err := cmd.GetUPID()

	assert.ErrorIs(t, err, ErrCommandTimeout)
	assert.Nil(t, u)
	assert.Less(t, time.Since(start), 2*time.Second)
	assert.True(t, mock.closed, "HECI must be closed after a timeout")
	// Once the client is known to hang, no further commands are attempted.
	assert.Equal(t, []uint8{CommandFeatureStateGet}, mock.commands())
}

func TestRequestWireFormat(t *testing.T) {
	mock := &mockHECI{responses: map[uint8]func([]byte) ([]byte, error){
		CommandFeatureStateGet: featureState(false),
		CommandFeatureStateSet: respond(statusResponse(CommandFeatureStateSet, StatusSuccess)),
		CommandPlatformIDGet:   respond(platformIDResponse(PlatformIDTypeBinary, 0xAA, 0xBB)),
	}}

	_, err := (&Command{Heci: mock}).GetUPID()
	require.NoError(t, err)

	mock.mu.Lock()
	defer mock.mu.Unlock()

	require.Len(t, mock.sent, 4)
	assert.Equal(t, []byte{CommandFeaturePlatformID, CommandFeatureStateGet, 0, 0}, mock.sent[0])
	assert.Equal(t, []byte{CommandFeaturePlatformID, CommandFeatureStateSet, 1, 0, FeatureStateEnabled}, mock.sent[1])
	assert.Equal(t, []byte{CommandFeaturePlatformID, CommandPlatformIDGet, 0, 0}, mock.sent[2])
	assert.Equal(t, []byte{CommandFeaturePlatformID, CommandFeatureStateSet, 1, 0, FeatureStateDisabled}, mock.sent[3])
}

func TestGetUPIDRestoresAfterReadTimeout(t *testing.T) {
	blocked := make(chan struct{})
	finished := make(chan struct{})
	mock := &mockHECI{responses: map[uint8]func([]byte) ([]byte, error){
		CommandFeatureStateGet: featureState(false),
		CommandFeatureStateSet: respond(statusResponse(CommandFeatureStateSet, StatusSuccess)),
		CommandPlatformIDGet: func([]byte) ([]byte, error) {
			<-blocked
			close(finished)

			return nil, errors.New("read canceled")
		},
	}}

	t.Cleanup(func() { close(blocked); <-finished })

	var restored []uint8

	recovery := &mockHECI{responses: map[uint8]func([]byte) ([]byte, error){
		CommandFeatureStateSet: featureStateSet(&restored),
	}}
	cmd := &Command{
		Heci:    mock,
		Timeout: 20 * time.Millisecond,
		newHECI: func() heci.GUIDInterface {
			assert.True(t, mock.closed, "close timed-out connection before recovery")

			return recovery
		},
	}

	u, err := cmd.GetUPID()
	assert.ErrorIs(t, err, ErrCommandTimeout)
	assert.Nil(t, u)
	assert.Equal(t, []uint8{FeatureStateDisabled}, restored)
	assert.Equal(t, UPIDGUID, recovery.guid)
	assert.True(t, recovery.closed)
	assert.True(t, cmd.timedOut, "recovery must not reuse the timed-out connection")
	assert.Equal(t, []uint8{CommandFeatureStateGet, CommandFeatureStateSet, CommandPlatformIDGet}, mock.commands())
}

// The firmware may apply FEATURE_STATE_SET(enable) even when its response
// never arrives, so the feature must still be disabled again.
func TestGetUPIDRestoresAfterLostEnableResponse(t *testing.T) {
	blocked := make(chan struct{})
	finished := make(chan struct{})
	mock := &mockHECI{responses: map[uint8]func([]byte) ([]byte, error){
		CommandFeatureStateGet: featureState(false),
		CommandFeatureStateSet: func([]byte) ([]byte, error) {
			<-blocked
			close(finished)

			return nil, errors.New("read canceled")
		},
	}}

	t.Cleanup(func() { close(blocked); <-finished })

	var restored []uint8

	recovery := &mockHECI{responses: map[uint8]func([]byte) ([]byte, error){
		CommandFeatureStateSet: featureStateSet(&restored),
	}}
	cmd := &Command{
		Heci:    mock,
		Timeout: 20 * time.Millisecond,
		newHECI: func() heci.GUIDInterface {
			assert.True(t, mock.closed, "close timed-out connection before recovery")

			return recovery
		},
	}

	u, err := cmd.GetUPID()
	assert.ErrorIs(t, err, ErrCommandTimeout)
	assert.Nil(t, u)
	assert.Equal(t, []uint8{FeatureStateDisabled}, restored)
	assert.True(t, recovery.closed)
	// The read is not attempted on the hung connection.
	assert.Equal(t, []uint8{CommandFeatureStateGet, CommandFeatureStateSet}, mock.commands())
}

func TestGetUPIDRestoresAfterEnableReceiveError(t *testing.T) {
	var sets []uint8

	mock := &mockHECI{responses: map[uint8]func([]byte) ([]byte, error){
		CommandFeatureStateGet: featureState(false),
		CommandFeatureStateSet: func(request []byte) ([]byte, error) {
			sets = append(sets, request[headerSize])
			if request[headerSize] == FeatureStateEnabled {
				return nil, errors.New("response lost")
			}

			return statusResponse(CommandFeatureStateSet, StatusSuccess), nil
		},
		CommandPlatformIDGet: respond(platformIDResponse(PlatformIDTypeBinary, 0xAA, 0xBB)),
	}}

	u, err := (&Command{Heci: mock}).GetUPID()
	require.NoError(t, err)
	require.NotNil(t, u)
	assert.Equal(t, []uint8{FeatureStateEnabled, FeatureStateDisabled}, sets)
}

func TestGetUPIDDoesNotRestoreWhenEnableRejected(t *testing.T) {
	var sets []uint8

	mock := &mockHECI{responses: map[uint8]func([]byte) ([]byte, error){
		CommandFeatureStateGet: featureState(false),
		CommandFeatureStateSet: func(request []byte) ([]byte, error) {
			sets = append(sets, request[headerSize])

			return statusResponse(CommandFeatureStateSet, StatusNotAllowedAfterEOP), nil
		},
		CommandPlatformIDGet: respond(statusResponse(CommandPlatformIDGet, StatusInvalidState)),
	}}

	u, err := (&Command{Heci: mock}).GetUPID()
	assert.ErrorIs(t, err, ErrInvalidState)
	assert.Nil(t, u)
	assert.Equal(t, []uint8{FeatureStateEnabled}, sets)
}

func TestGetUPIDClosesEachConnection(t *testing.T) {
	mock := &mockHECI{responses: map[uint8]func([]byte) ([]byte, error){
		CommandFeatureStateGet: featureState(true),
		CommandPlatformIDGet:   respond(platformIDResponse(PlatformIDTypeBinary, 0xAA, 0xBB)),
	}}
	cmd := &Command{Heci: mock}

	for range 2 {
		_, err := cmd.GetUPID()
		require.NoError(t, err)
	}

	assert.Equal(t, 2, mock.closeCount)
}
