/*********************************************************************
 * Copyright (c) Intel Corporation 2026
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/

package cli

import (
	"testing"

	"github.com/alecthomas/kong"
	"github.com/sirupsen/logrus"
	logtest "github.com/sirupsen/logrus/hooks/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLogConfigFileUse(t *testing.T) {
	var app struct {
		AmtInfo   struct{} `cmd:"" name:"amtinfo"`
		Configure struct{} `cmd:"" name:"configure"`
	}

	parser, err := kong.New(&app)
	require.NoError(t, err)

	tests := []struct {
		name      string
		args      []string
		wantLevel logrus.Level
	}{
		{name: "amtinfo keeps it at debug", args: []string{"amtinfo"}, wantLevel: logrus.DebugLevel},
		{name: "other commands show it", args: []string{"configure"}, wantLevel: logrus.InfoLevel},
		{name: "unparsed command shows it", args: nil, wantLevel: logrus.InfoLevel},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			var ctx *kong.Context

			if tt.args != nil {
				ctx, err = parser.Parse(tt.args)
				require.NoError(t, err)
			}

			hook := logtest.NewGlobal()
			defer hook.Reset()

			originalLevel := logrus.GetLevel()
			defer logrus.SetLevel(originalLevel)

			logrus.SetLevel(logrus.DebugLevel)

			logConfigFileUse(ctx, "config.yaml")

			require.Len(t, hook.AllEntries(), 1)
			assert.Equal(t, tt.wantLevel, hook.LastEntry().Level)
			assert.Contains(t, hook.LastEntry().Message, "Using configuration file: config.yaml")
		})
	}
}
