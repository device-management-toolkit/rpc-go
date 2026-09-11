/*********************************************************************
 * Copyright (c) Intel Corporation 2025
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/
package commands

import (
	"bytes"
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
)

func TestWarnIfCredentialsOnCLI(t *testing.T) {
	tests := []struct {
		name       string
		args       []string
		value      string
		envVar     string
		wantNotice bool
		wantEnv    string
	}{
		{
			name:       "long flag with separate value",
			args:       []string{"rpc", "configure", "tls", "--eaPassword", "secret"},
			value:      "secret",
			wantNotice: true,
		},
		{
			name:       "long flag with equals value",
			args:       []string{"rpc", "configure", "wired", "--ieee8021xPrivateKey=private-key"},
			value:      "private-key",
			wantNotice: true,
		},
		{
			name:       "short flag with attached value",
			args:       []string{"rpc", "activate", "-ksecret"},
			value:      "secret",
			envVar:     "CONFIG_ENCRYPTION_KEY",
			wantNotice: true,
			wantEnv:    "CONFIG_ENCRYPTION_KEY=<value>",
		},
		{
			name:       "value from environment or config",
			args:       []string{"rpc", "configure", "mebx"},
			value:      "secret",
			envVar:     "MEBX_PASSWORD",
			wantNotice: false,
		},
		{
			name:       "empty value",
			args:       []string{"rpc", "configure", "tls", "--eaPassword", ""},
			value:      " ",
			wantNotice: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			oldOutput := logrus.StandardLogger().Out
			oldLevel := logrus.GetLevel()
			restoreArgs := SetParsedCLIArgs(tt.args[1:])

			defer func() {
				restoreArgs()

				logrus.SetOutput(oldOutput)
				logrus.SetLevel(oldLevel)
			}()

			var output bytes.Buffer

			logrus.SetOutput(&output)
			logrus.SetLevel(logrus.WarnLevel)

			WarnIfCredentialsOnCLI(CredentialCLI{
				Value:    tt.value,
				EnvVar:   tt.envVar,
				FlagName: []string{"eaPassword", "ieee8021xPrivateKey", "k"},
			})

			if tt.wantNotice {
				require.Contains(t, output.String(), "SECURITY WARNING")
			} else {
				require.NotContains(t, output.String(), "SECURITY WARNING")
			}

			if tt.wantEnv != "" {
				require.Contains(t, output.String(), tt.wantEnv)
			}
		})
	}
}
