/*********************************************************************
 * Copyright (c) Intel Corporation 2026
 * SPDX-License-Identifier: Apache-2.0
 *********************************************************************/

package diagnostics

import (
	"context"
	"errors"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/device-management-toolkit/rpc-go/v2/internal/commands"
	mock "github.com/device-management-toolkit/rpc-go/v2/internal/mocks"
	"github.com/device-management-toolkit/rpc-go/v2/pkg/pthi"
	"github.com/device-management-toolkit/rpc-go/v2/pkg/utils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

var (
	errLMEUnavailable = errors.New("lme unavailable")
	errCloseFailed    = errors.New("close failed")
)

func TestDiagnosticsBaseCmd_QuietIsRuntimeOnly(t *testing.T) {
	field, ok := reflect.TypeFor[DiagnosticsBaseCmd]().FieldByName("quiet")
	require.True(t, ok)
	assert.Equal(t, "-", field.Tag.Get("kong"), "quiet must stay hidden from Kong, env vars and config.yaml")
}

func TestCIRACmd_CollectReturnsTheLog(t *testing.T) {
	ctrl := gomock.NewController(t)
	mockAMT := mock.NewMockInterface(ctrl)

	want := pthi.GetCiraLogResponse{Version: 1}
	want.CiraStatusSummary.IsTunnelOpened = 1

	mockAMT.EXPECT().GetCiraLog().Return(want, nil)

	cmd := &CIRACmd{}

	var got pthi.GetCiraLogResponse

	out := captureStdout(t, func() {
		var err error

		got, err = cmd.Collect(&commands.Context{AMTCommand: mockAMT})
		require.NoError(t, err)
	})

	assert.Equal(t, want, got)
	assert.Empty(t, out)
	assert.Empty(t, cmd.Output, "Collect must not pick an output file")
}

func TestCIRACmd_CollectUnsupportedFirmware(t *testing.T) {
	ctrl := gomock.NewController(t)
	mockAMT := mock.NewMockInterface(ctrl)
	mockAMT.EXPECT().GetCiraLog().Return(pthi.GetCiraLogResponse{}, errors.New("empty response from AMT"))

	_, err := (&CIRACmd{}).Collect(&commands.Context{AMTCommand: mockAMT})

	require.ErrorIs(t, err, ErrCIRALogNotSupported)
	assert.EqualError(t, err, "CIRA Log feature is not supported in this firmware version")
}

func TestCIRACmd_CollectPassesOtherErrorsOn(t *testing.T) {
	ctrl := gomock.NewController(t)
	mockAMT := mock.NewMockInterface(ctrl)
	readErr := errors.New("heci read failed")
	mockAMT.EXPECT().GetCiraLog().Return(pthi.GetCiraLogResponse{}, readErr)

	_, err := (&CIRACmd{}).Collect(&commands.Context{AMTCommand: mockAMT})

	assert.Equal(t, readErr, err)
}

func TestCIRALogText_MatchesTheFileRunWrites(t *testing.T) {
	ctrl := gomock.NewController(t)
	mockAMT := mock.NewMockInterface(ctrl)

	log := pthi.GetCiraLogResponse{Version: 2}
	log.CiraStatusSummary.LastKeepAlive = 1700000000
	log.FailedConnectionLogEntry.InterfaceData[0].IPParameters.IpAddress = 0x0100a8c0

	mockAMT.EXPECT().GetCiraLog().Return(log, nil)

	output := filepath.Join(t.TempDir(), "cira.txt")
	cmd := &CIRACmd{Output: output}
	cmd.quiet = true

	require.NoError(t, cmd.Run(&commands.Context{AMTCommand: mockAMT}))

	written, err := os.ReadFile(output)
	require.NoError(t, err)

	text, err := CIRALogText(log)
	require.NoError(t, err)
	assert.Equal(t, string(written), text)
	assert.Contains(t, text, "Version = 2")
}

func TestCSMECmd_CollectReturnsTheFlashLog(t *testing.T) {
	ctrl := gomock.NewController(t)
	mockAMT := mock.NewMockInterface(ctrl)
	mockAMT.EXPECT().GetFlog().Return([]byte{0x01, 0x02, 0x03}, nil)

	cmd := &CSMECmd{}

	var got []byte

	out := captureStdout(t, func() {
		var err error

		got, err = cmd.Collect(&commands.Context{AMTCommand: mockAMT})
		require.NoError(t, err)
	})

	assert.Equal(t, []byte{0x01, 0x02, 0x03}, got)
	assert.Empty(t, out)
	assert.Empty(t, cmd.Output, "Collect must not pick an output file")
}

func TestCSMECmd_CollectWrapsTheReadError(t *testing.T) {
	ctrl := gomock.NewController(t)
	mockAMT := mock.NewMockInterface(ctrl)
	readErr := errors.New("hotham open failed")
	mockAMT.EXPECT().GetFlog().Return(nil, readErr)

	_, err := (&CSMECmd{}).Collect(&commands.Context{AMTCommand: mockAMT})

	require.ErrorIs(t, err, readErr)
	assert.EqualError(t, err, "failed to retrieve flash log: hotham open failed")
}

func TestRenderWSMANClasses_RendersFetchFailuresLikeTheCLI(t *testing.T) {
	classes := []WSMANClassData{
		{Class: "AMT_GeneralSettings", Data: map[string]string{"HostName": "device"}},
		{Class: "CIM_Chassis", Err: errLMEUnavailable},
	}

	got, err := RenderWSMANClasses(classes, "json")
	require.NoError(t, err)

	want, err := renderResults([]classResult{
		{Class: "AMT_GeneralSettings", Data: map[string]string{"HostName": "device"}},
		{Class: "CIM_Chassis", Data: classFetchErrorData{Class: "CIM_Chassis", Status: "fetch_failed", Message: "lme unavailable"}},
	}, "json")
	require.NoError(t, err)
	assert.Equal(t, string(want), string(got))
}

func TestRenderWSMANClasses_RejectsUnknownFormat(t *testing.T) {
	_, err := RenderWSMANClasses(nil, "yaml")

	assert.EqualError(t, err, "unsupported format: yaml")
}

// fakeLMETransport stands in for the LME fallback transport.
type fakeLMETransport struct {
	closed int
}

func (f *fakeLMETransport) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, errLMEUnavailable
}

func (f *fakeLMETransport) Close() error {
	f.closed++

	return nil
}

// useFakeLMETransport makes newWSMANMessages fall back to a fake LME transport.
// It skips the test when an LMS listens on this host, as newWSMANMessages then
// does not fall back to LME.
func useFakeLMETransport(t *testing.T) *fakeLMETransport {
	t.Helper()

	dialer := &net.Dialer{Timeout: time.Second}

	conn, err := dialer.DialContext(context.Background(), "tcp4", utils.LMSAddress+":"+utils.LMSPort)
	if err == nil {
		_ = conn.Close()

		t.Skip("skipped: an LMS listens on this host, so no LME fallback transport is opened")
	}

	fake := &fakeLMETransport{}
	previous := newLMETransport
	newLMETransport = func() lmeTransport { return fake }

	t.Cleanup(func() { newLMETransport = previous })

	return fake
}

func TestWSManGetCmd_FetchReportsEveryClassAndClosesTheLMETransport(t *testing.T) {
	fake := useFakeLMETransport(t)

	cmd := &WSManGetCmd{Class: []string{"AMT_GeneralSettings", "CIM_Chassis"}}

	classes, err := cmd.Fetch(&commands.Context{AMTPassword: "P@ssw0rd"})

	var fetchErr *wsmanFetchError
	require.ErrorAs(t, err, &fetchErr)
	assert.Equal(t, 2, fetchErr.failed)
	assert.Equal(t, 2, fetchErr.total)
	require.Len(t, classes, 2)
	assert.Equal(t, "AMT_GeneralSettings", classes[0].Class)
	assert.Equal(t, "CIM_Chassis", classes[1].Class)

	for _, class := range classes {
		require.ErrorIs(t, class.Err, errLMEUnavailable)
		assert.Nil(t, class.Data)
	}

	assert.Equal(t, 1, fake.closed)
}

func TestWSManGetCmd_FetchOneClassReturnsItsErrorAndClosesTheLMETransport(t *testing.T) {
	fake := useFakeLMETransport(t)

	cmd := &WSManGetCmd{Class: []string{"CIM_Chassis"}}

	classes, err := cmd.Fetch(&commands.Context{AMTPassword: "P@ssw0rd"})

	require.ErrorIs(t, err, errLMEUnavailable)
	assert.ErrorContains(t, err, "failed to retrieve WSMAN class CIM_Chassis: ")
	require.Len(t, classes, 1)
	require.ErrorIs(t, classes[0].Err, errLMEUnavailable)
	assert.Equal(t, 1, fake.closed)
}

func TestWSManGetCmd_FetchRejectsInvalidClassesBeforeConnecting(t *testing.T) {
	previous := newLMETransport
	newLMETransport = func() lmeTransport {
		t.Fatal("Fetch connected before validating the classes")

		return nil
	}

	t.Cleanup(func() { newLMETransport = previous })

	classes, err := (&WSManGetCmd{Class: []string{"Bogus_Class"}}).Fetch(&commands.Context{AMTPassword: "P@ssw0rd"})

	require.EqualError(t, err, "unsupported WSMAN class: Bogus_Class")
	assert.Nil(t, classes)
}

// fakeWSMANClient records how closeWSMANClient releases it.
type fakeWSMANClient struct {
	closeErr       error
	closedConn     int
	closedIdleConn int
}

func (f *fakeWSMANClient) CloseConnection() error {
	f.closedConn++

	return f.closeErr
}

func (f *fakeWSMANClient) CloseIdleConnections() { f.closedIdleConn++ }

func TestCloseWSMANClient_ReleasesConnectionsAndTransport(t *testing.T) {
	tests := []struct {
		name      string
		closeErr  error
		transport bool
	}{
		{"LMS keep-alive client", nil, false},
		{"client without a TCP connection, LME transport", errCloseFailed, true},
	}

	for _, tt := range tests {
		tt := tt

		t.Run(tt.name, func(t *testing.T) {
			client := &fakeWSMANClient{closeErr: tt.closeErr}

			var transport *fakeLMETransport

			var closer lmeTransport

			if tt.transport {
				transport = &fakeLMETransport{}
				closer = transport
			}

			closeWSMANClient(client, closer)

			assert.Equal(t, 1, client.closedConn)
			assert.Equal(t, 1, client.closedIdleConn)

			if tt.transport {
				assert.Equal(t, 1, transport.closed)
			}
		})
	}
}

func TestBundleCmd_CollectReturnsTheManifestWithoutPrinting(t *testing.T) {
	output := filepath.Join(t.TempDir(), "bundle")
	createdAt := time.Date(2026, 11, 3, 10, 0, 0, 0, time.UTC)

	cmd := BundleCmd{
		Output: output,
		now:    func() time.Time { return createdAt },
		collectors: []bundleCollector{
			{name: "working", fileName: "working.txt", collect: func(path string) error {
				return os.WriteFile(path, []byte("ok"), 0o644)
			}},
			{name: "broken", fileName: "broken.txt", collect: func(string) error { return errLMEUnavailable }},
		},
	}

	var (
		result *BundleResult
		err    error
	)

	out := captureStdout(t, func() { result, err = cmd.Collect(&commands.Context{}) })

	require.NoError(t, err)
	assert.Empty(t, out)
	require.NotNil(t, result)
	assert.Equal(t, output+".zip", result.Path)
	assert.Equal(t, BundleManifest{
		CreatedAt: createdAt,
		Collectors: []BundleCollectorResult{
			{Name: "working", File: "working.txt", Status: "success"},
			{Name: "broken", Status: "failed", Error: "lme unavailable"},
		},
	}, result.Manifest)
	assert.Equal(t, 1, result.Manifest.Incomplete())
	assert.FileExists(t, result.Path)
}

func TestBundleCmd_CollectReturnsTheResultWhenNothingWasCollected(t *testing.T) {
	output := filepath.Join(t.TempDir(), "bundle.zip")

	cmd := BundleCmd{
		Output: output,
		collectors: []bundleCollector{
			{name: "broken", fileName: "broken.txt", collect: func(string) error { return errLMEUnavailable }},
		},
	}

	result, err := cmd.Collect(&commands.Context{})

	require.EqualError(t, err, "no diagnostics were collected (manifest written to "+output+"): broken: lme unavailable")
	require.NotNil(t, result)
	assert.Equal(t, output, result.Path)
	assert.Equal(t, 1, result.Manifest.Incomplete())
	assert.FileExists(t, output)
}

func TestBundleCmd_RunPrintsWhatItPrintedBefore(t *testing.T) {
	output := filepath.Join(t.TempDir(), "bundle.zip")

	cmd := BundleCmd{
		Output: output,
		collectors: []bundleCollector{
			{name: "working", fileName: "working.txt", collect: func(path string) error {
				return os.WriteFile(path, []byte("ok"), 0o644)
			}},
			{name: "broken", fileName: "broken.txt", collect: func(string) error { return errLMEUnavailable }},
		},
	}

	var err error

	out := captureStdout(t, func() { err = cmd.Run(&commands.Context{}) })

	require.NoError(t, err)
	assert.Equal(t, "Diagnostics bundle successfully created\nOutput file: "+output+"\n"+
		"Warning: 1 diagnostic collector(s) were incomplete; see manifest.json for details\n", out)
}
