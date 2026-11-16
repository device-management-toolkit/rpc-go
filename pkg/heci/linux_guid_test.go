//go:build linux
// +build linux

/*********************************************************************
 * Copyright (c) Intel Corporation 2026
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/
package heci

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A regular file stands in for an MEI device that hosts no client with the
// requested GUID: the connect ioctl fails on it with ENOTTY, as the MEI
// driver does.
func TestInitWithGUIDClassifiesConnectError(t *testing.T) {
	const guid = "{92136C79-5FEA-4CFD-980E-23BE07FA5E9F}"

	dir := t.TempDir()
	noClient := filepath.Join(dir, "mei-no-client")
	missing := filepath.Join(dir, "mei-missing")

	require.NoError(t, os.WriteFile(noClient, nil, 0o600))

	tests := []struct {
		name         string
		guid         string
		paths        []string
		wantErr      error
		wantNotFound bool
	}{
		{
			name:         "device without the client",
			guid:         guid,
			paths:        []string{noClient},
			wantErr:      syscall.ENOTTY,
			wantNotFound: true,
		},
		{
			name:         "client missing on the node after an absent one",
			guid:         guid,
			paths:        []string{missing, noClient},
			wantErr:      syscall.ENOTTY,
			wantNotFound: true,
		},
		{
			name:    "no MEI device",
			guid:    guid,
			paths:   []string{missing},
			wantErr: fs.ErrNotExist,
		},
		{
			name:  "invalid GUID",
			guid:  "not-a-guid",
			paths: []string{noClient},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			original := meiDevicePaths
			meiDevicePaths = tc.paths

			t.Cleanup(func() { meiDevicePaths = original })

			err := NewDriver().InitWithGUID(tc.guid)
			require.Error(t, err)

			if tc.wantErr != nil {
				assert.ErrorIs(t, err, tc.wantErr)
			}

			assert.Equal(t, tc.wantNotFound, errors.Is(err, ErrClientNotFound))
		})
	}
}
