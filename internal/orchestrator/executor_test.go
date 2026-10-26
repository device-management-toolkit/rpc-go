/*********************************************************************
 * Copyright (c) Intel Corporation 2026
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/

package orchestrator

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/device-management-toolkit/go-wsman-messages/v2/pkg/config"
	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeRPCRecordEnv turns the test binary into a fake rpc binary. When it is set,
// TestMain writes the process argv as JSON to the file it names and exits, so
// tests can see which binary a CLIExecutor ran and with which arguments.
const fakeRPCRecordEnv = "RPC_ORCHESTRATOR_TEST_ARGV_FILE"

func TestMain(m *testing.M) {
	if record := os.Getenv(fakeRPCRecordEnv); record != "" {
		os.Exit(recordArgv(record))
	}

	// go test passes -test.* flags first, so rpc arguments mean a child that lost fakeRPCRecordEnv.
	if len(os.Args) > 1 && !strings.HasPrefix(os.Args[1], "-") {
		os.Exit(3)
	}

	os.Exit(m.Run())
}

// recordArgv writes os.Args to path and returns the exit code for the fake rpc.
func recordArgv(path string) int {
	data, err := json.Marshal(os.Args)
	if err != nil {
		return 1
	}

	if err := os.WriteFile(path, data, 0o600); err != nil {
		return 1
	}

	return 0
}

// readArgv returns the argv a fake rpc process recorded in path.
func readArgv(t *testing.T, path string) []string {
	t.Helper()

	data, err := os.ReadFile(path)
	require.NoError(t, err)

	var argv []string

	require.NoError(t, json.Unmarshal(data, &argv))

	return argv
}

// copyTestBinary copies the running test binary to a fake rpc in a temporary
// directory, so a test can tell it apart from the current executable.
func copyTestBinary(t *testing.T) string {
	t.Helper()

	current, err := os.Executable()
	require.NoError(t, err)

	data, err := os.ReadFile(current)
	require.NoError(t, err)

	fake := filepath.Join(t.TempDir(), "fake-rpc"+filepath.Ext(current))
	require.NoError(t, os.WriteFile(fake, data, 0o700))

	return fake
}

func TestCLIExecutor_RunsExecutable(t *testing.T) {
	current, err := os.Executable()
	require.NoError(t, err)

	fake := copyTestBinary(t)

	tests := []struct {
		name       string
		executable string
		wantArgv0  string
	}{
		{name: "current executable when unset", executable: "", wantArgv0: current},
		{name: "configured executable", executable: fake, wantArgv0: fake},
	}

	for _, tt := range tests {
		tt := tt

		t.Run(tt.name, func(t *testing.T) {
			record := filepath.Join(t.TempDir(), "argv.json")
			executor := &CLIExecutor{Executable: tt.executable}

			err := executor.Execute([]string{rpcExecutableName, "configure", "mebx"}, map[string]string{fakeRPCRecordEnv: record})
			require.NoError(t, err)

			assert.Equal(t, []string{tt.wantArgv0, "configure", "mebx"}, readArgv(t, record))
		})
	}
}

func TestProfileOrchestrator_StepsRunTheSetExecutor(t *testing.T) {
	// baseArgs adds -v at debug level; pin the level so the argv is exact.
	level := log.GetLevel()

	log.SetLevel(log.InfoLevel)
	t.Cleanup(func() { log.SetLevel(level) })

	fake := copyTestBinary(t)
	record := filepath.Join(t.TempDir(), "argv.json")
	// The step builds its own environment; the fake rpc inherits this one.
	t.Setenv(fakeRPCRecordEnv, record)

	po := NewProfileOrchestrator(config.Configuration{}, "", "", false)
	po.SetExecutor(&CLIExecutor{Executable: fake})

	require.NoError(t, po.executeEnableWiFi())

	assert.Equal(t, []string{fake, "configure", "wifisync", "--oswifisync=false", "--uefiwifisync=false"}, readArgv(t, record))
}
