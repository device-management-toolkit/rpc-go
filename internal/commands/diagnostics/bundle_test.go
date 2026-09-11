/*********************************************************************
 * Copyright (c) Intel Corporation 2026
 * SPDX-License-Identifier: Apache-2.0
 *********************************************************************/

package diagnostics

import (
	"archive/zip"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/device-management-toolkit/rpc-go/v2/internal/commands"
	mock "github.com/device-management-toolkit/rpc-go/v2/internal/mocks"
	"github.com/device-management-toolkit/rpc-go/v2/pkg/pthi"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

func TestBundleCommand_DefaultCollectors(t *testing.T) {
	ctrl := gomock.NewController(t)
	t.Cleanup(ctrl.Finish)

	mockAMT := mock.NewMockInterface(ctrl)
	mockAMT.EXPECT().GetCiraLog().Return(pthi.GetCiraLogResponse{}, nil)
	mockAMT.EXPECT().GetFlog().Return([]byte{0x01, 0x02, 0x03}, nil)

	tempDir := t.TempDir()
	outputFile := filepath.Join(tempDir, "diagnostics.zip")

	var wsmanCmd *WSManGetCmd

	cmd := BundleCmd{
		Output: outputFile,
		runWSMan: func(command *WSManGetCmd, _ *commands.Context) error {
			wsmanCmd = command

			return os.WriteFile(command.Output, []byte(`[{"class":"AMT_GeneralSettings","data":{}}]`), 0o644)
		},
	}

	require.NoError(t, cmd.Run(&commands.Context{AMTCommand: mockAMT}))
	require.NotNil(t, wsmanCmd)
	assert.True(t, wsmanCmd.All)
	assert.True(t, wsmanCmd.quiet)
	assert.Equal(t, "json", wsmanCmd.Format)
	assert.Equal(t, "wsman.json", filepath.Base(wsmanCmd.Output))

	archive, err := zip.OpenReader(outputFile)
	require.NoError(t, err)

	t.Cleanup(func() { require.NoError(t, archive.Close()) })

	entries := make(map[string]bool, len(archive.File))
	for _, file := range archive.File {
		entries[file.Name] = true
	}

	assert.True(t, entries["cira.txt"])
	assert.True(t, entries["csme_flash_log.bin"])
	assert.True(t, entries["wsman.json"])
	assert.True(t, entries["manifest.json"])

	manifestData := readZipEntry(t, archive, "manifest.json")

	var manifest bundleManifest
	require.NoError(t, json.Unmarshal(manifestData, &manifest))
	require.Len(t, manifest.Collectors, 3)

	for _, collector := range manifest.Collectors {
		assert.Equal(t, "success", collector.Status)
	}
}

func TestBundleCommand_QuietCollectorOutput(t *testing.T) {
	ctrl := gomock.NewController(t)
	t.Cleanup(ctrl.Finish)

	mockAMT := mock.NewMockInterface(ctrl)
	mockAMT.EXPECT().GetCiraLog().Return(pthi.GetCiraLogResponse{}, nil)
	mockAMT.EXPECT().GetFlog().Return([]byte{0x01}, nil)

	outputFile := filepath.Join(t.TempDir(), "diagnostics.zip")
	cmd := BundleCmd{
		Output: outputFile,
		runWSMan: func(command *WSManGetCmd, _ *commands.Context) error {
			return os.WriteFile(command.Output, []byte(`[]`), 0o644)
		},
	}

	stdout := captureStdout(t, func() {
		require.NoError(t, cmd.Run(&commands.Context{AMTCommand: mockAMT}))
	})

	assert.NotContains(t, stdout, "successfully retrieved")
	assert.Equal(t, "Diagnostics bundle successfully created\nOutput file: "+outputFile+"\n", stdout)
}

func TestBundleCommand_DefaultCollectorsRecordsPartialWSMan(t *testing.T) {
	ctrl := gomock.NewController(t)
	t.Cleanup(ctrl.Finish)

	mockAMT := mock.NewMockInterface(ctrl)
	mockAMT.EXPECT().GetCiraLog().Return(pthi.GetCiraLogResponse{}, nil)
	mockAMT.EXPECT().GetFlog().Return([]byte{0x01, 0x02, 0x03}, nil)

	outputFile := filepath.Join(t.TempDir(), "diagnostics.zip")
	cmd := BundleCmd{
		Output: outputFile,
		runWSMan: func(command *WSManGetCmd, _ *commands.Context) error {
			require.NoError(t, os.WriteFile(command.Output, []byte(`[{"class":"IPS_SecIOService","data":{"status":"fetch_failed"}}]`), 0o644))

			return &wsmanFetchError{failed: 1, total: 52, last: errors.New("destination unreachable")}
		},
	}

	require.NoError(t, cmd.Run(&commands.Context{AMTCommand: mockAMT}))

	archive, err := zip.OpenReader(outputFile)
	require.NoError(t, err)

	t.Cleanup(func() { require.NoError(t, archive.Close()) })

	assert.NotEmpty(t, readZipEntry(t, archive, "wsman.json"))

	manifestData := readZipEntry(t, archive, "manifest.json")

	var manifest bundleManifest
	require.NoError(t, json.Unmarshal(manifestData, &manifest))
	require.Len(t, manifest.Collectors, 3)
	assert.Equal(t, bundleCollectorResult{Name: "wsman", File: "wsman.json", Status: "partial", Error: "1 of 52 WSMAN classes failed to retrieve"}, manifest.Collectors[2])
}

func TestBundleCommand_DefaultCollectorsFailsWSManWhenAllClassesFail(t *testing.T) {
	ctrl := gomock.NewController(t)
	t.Cleanup(ctrl.Finish)

	mockAMT := mock.NewMockInterface(ctrl)
	mockAMT.EXPECT().GetCiraLog().Return(pthi.GetCiraLogResponse{}, nil)
	mockAMT.EXPECT().GetFlog().Return([]byte{0x01}, nil)

	outputFile := filepath.Join(t.TempDir(), "diagnostics.zip")
	cmd := BundleCmd{
		Output: outputFile,
		runWSMan: func(command *WSManGetCmd, _ *commands.Context) error {
			require.NoError(t, os.WriteFile(command.Output, []byte(`[]`), 0o644))

			return &wsmanFetchError{failed: 52, total: 52, last: errors.New("connection refused")}
		},
	}

	require.NoError(t, cmd.Run(&commands.Context{AMTCommand: mockAMT}))

	archive, err := zip.OpenReader(outputFile)
	require.NoError(t, err)

	t.Cleanup(func() { require.NoError(t, archive.Close()) })

	for _, file := range archive.File {
		assert.NotEqual(t, "wsman.json", file.Name)
	}

	var manifest bundleManifest
	require.NoError(t, json.Unmarshal(readZipEntry(t, archive, "manifest.json"), &manifest))
	require.Len(t, manifest.Collectors, 3)
	assert.Equal(t, bundleCollectorResult{Name: "wsman", Status: "failed", Error: "all 52 WSMAN classes failed to retrieve: connection refused"}, manifest.Collectors[2])
}

func TestBundleCommand_SuggestsSkipAMTCertCheckOnCertificateFailure(t *testing.T) {
	ctrl := gomock.NewController(t)
	t.Cleanup(ctrl.Finish)

	mockAMT := mock.NewMockInterface(ctrl)
	mockAMT.EXPECT().GetCiraLog().Return(pthi.GetCiraLogResponse{}, nil)
	mockAMT.EXPECT().GetFlog().Return([]byte{0x01}, nil)

	certErr := &url.Error{
		Op:  "Post",
		URL: "https://127.0.0.1:16993/wsman",
		Err: &tls.CertificateVerificationError{Err: errors.New("x509: certificate signed by unknown authority")},
	}

	outputFile := filepath.Join(t.TempDir(), "diagnostics.zip")
	cmd := BundleCmd{
		Output: outputFile,
		runWSMan: func(*WSManGetCmd, *commands.Context) error {
			return &wsmanFetchError{failed: 52, total: 52, last: certErr}
		},
	}

	require.NoError(t, cmd.Run(&commands.Context{AMTCommand: mockAMT}))

	archive, err := zip.OpenReader(outputFile)
	require.NoError(t, err)

	t.Cleanup(func() { require.NoError(t, archive.Close()) })

	var manifest bundleManifest
	require.NoError(t, json.Unmarshal(readZipEntry(t, archive, "manifest.json"), &manifest))
	require.Len(t, manifest.Collectors, 3)
	assert.Equal(t, "failed", manifest.Collectors[2].Status)
	assert.Contains(t, manifest.Collectors[2].Error, "retry with --skip-amt-cert-check")
}

func TestBundleCommand_ReturnsErrorWhenNothingCollected(t *testing.T) {
	outputFile := filepath.Join(t.TempDir(), "diagnostics.zip")
	cmd := BundleCmd{
		Output: outputFile,
		collectors: []bundleCollector{
			{name: "cira", fileName: "cira.txt", collect: func(string) error { return errors.New("not supported") }},
			{name: "wsman", fileName: "wsman.json", collect: func(string) error { return errors.New("all 52 WSMAN classes failed") }},
		},
	}

	err := cmd.Run(&commands.Context{})

	require.Error(t, err)
	assert.Equal(t, "no diagnostics were collected (manifest written to "+outputFile+"): cira: not supported; wsman: all 52 WSMAN classes failed", err.Error())

	archive, openErr := zip.OpenReader(outputFile)
	require.NoError(t, openErr)

	t.Cleanup(func() { require.NoError(t, archive.Close()) })

	require.Len(t, archive.File, 1)
	assert.Equal(t, "manifest.json", archive.File[0].Name)

	var manifest bundleManifest
	require.NoError(t, json.Unmarshal(readZipEntry(t, archive, "manifest.json"), &manifest))
	assert.Equal(t, []bundleCollectorResult{
		{Name: "cira", Status: "failed", Error: "not supported"},
		{Name: "wsman", Status: "failed", Error: "all 52 WSMAN classes failed"},
	}, manifest.Collectors)
}

func TestBundleCommand_CreatesBundleAndRecordsCollectorFailures(t *testing.T) {
	tempDir := t.TempDir()
	outputFile := filepath.Join(tempDir, "diagnostics.zip")
	createdAt := time.Date(2026, time.September, 9, 5, 47, 40, 0, time.UTC)

	cmd := BundleCmd{
		Output: outputFile,
		now:    func() time.Time { return createdAt },
		collectors: []bundleCollector{
			{
				name:     "working",
				fileName: "working.txt",
				collect: func(output string) error {
					return os.WriteFile(output, []byte("diagnostic data"), 0o644)
				},
			},
			{
				name:     "unsupported",
				fileName: "unsupported.txt",
				collect: func(output string) error {
					require.NoError(t, os.WriteFile(output, []byte("partial data"), 0o644))

					return errors.New("not supported")
				},
			},
			{
				name:     "missing-output",
				fileName: "missing.txt",
				collect:  func(string) error { return nil },
			},
			{
				name:     "partial",
				fileName: "partial.json",
				collect: func(output string) error {
					require.NoError(t, os.WriteFile(output, []byte(`{"partial":true}`), 0o644))

					return partialCollectionError{err: errors.New("one class failed")}
				},
			},
		},
	}

	require.NoError(t, cmd.Run(&commands.Context{}))
	assert.FileExists(t, outputFile)

	archive, err := zip.OpenReader(outputFile)
	require.NoError(t, err)

	defer archive.Close()

	files := make(map[string][]byte, len(archive.File))
	for _, file := range archive.File {
		reader, openErr := file.Open()
		require.NoError(t, openErr)

		data, readErr := io.ReadAll(reader)
		require.NoError(t, readErr)
		require.NoError(t, reader.Close())

		files[file.Name] = data
	}

	assert.Equal(t, []byte("diagnostic data"), files["working.txt"])
	assert.NotContains(t, files, "unsupported.txt")
	assert.Equal(t, []byte(`{"partial":true}`), files["partial.json"])

	var manifest bundleManifest
	require.NoError(t, json.Unmarshal(files["manifest.json"], &manifest))
	assert.Equal(t, createdAt, manifest.CreatedAt)
	require.Len(t, manifest.Collectors, 4)
	assert.Equal(t, bundleCollectorResult{Name: "working", File: "working.txt", Status: "success"}, manifest.Collectors[0])
	assert.Equal(t, bundleCollectorResult{Name: "unsupported", Status: "failed", Error: "not supported"}, manifest.Collectors[1])
	assert.Equal(t, "missing-output", manifest.Collectors[2].Name)
	assert.Equal(t, "failed", manifest.Collectors[2].Status)
	assert.Contains(t, manifest.Collectors[2].Error, "collector did not create missing.txt")
	assert.Equal(t, bundleCollectorResult{Name: "partial", File: "partial.json", Status: "partial", Error: "one class failed"}, manifest.Collectors[3])
}

func TestBundleCommand_DefaultOutputName(t *testing.T) {
	originalDir, err := os.Getwd()
	require.NoError(t, err)

	tempDir := t.TempDir()
	require.NoError(t, os.Chdir(tempDir))

	defer func() { require.NoError(t, os.Chdir(originalDir)) }()

	cmd := BundleCmd{
		now: func() time.Time { return time.Date(2026, time.September, 9, 5, 47, 40, 0, time.UTC) },
		collectors: []bundleCollector{
			{
				name:     "working",
				fileName: "working.txt",
				collect: func(output string) error {
					return os.WriteFile(output, []byte("diagnostic data"), 0o644)
				},
			},
		},
	}

	require.NoError(t, cmd.Run(&commands.Context{}))
	assert.Equal(t, "20260909_054740_diagnostics_bundle.zip", cmd.Output)
	assert.FileExists(t, cmd.Output)
}

func readZipEntry(t *testing.T, archive *zip.ReadCloser, name string) []byte {
	t.Helper()

	for _, file := range archive.File {
		if file.Name != name {
			continue
		}

		reader, err := file.Open()
		require.NoError(t, err)
		data, err := io.ReadAll(reader)
		require.NoError(t, err)
		require.NoError(t, reader.Close())

		return data
	}

	t.Fatalf("ZIP entry %q not found", name)

	return nil
}

func captureStdout(t *testing.T, run func()) string {
	t.Helper()

	reader, writer, err := os.Pipe()
	require.NoError(t, err)

	originalStdout := os.Stdout
	os.Stdout = writer

	defer func() { os.Stdout = originalStdout }()

	run()

	require.NoError(t, writer.Close())

	output, err := io.ReadAll(reader)
	require.NoError(t, err)
	require.NoError(t, reader.Close())

	return string(output)
}
