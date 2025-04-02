/*********************************************************************
 * Copyright (c) Intel Corporation 2024
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/

package smb

import (
	"errors"
	"os/user"
	"testing"

	"github.com/open-amt-cloud-toolkit/rpc-go/v2/pkg/utils"

	"github.com/stretchr/testify/assert"
)

var MockPRSuccess = new(MockPasswordReaderSuccess)
var MockPRFail = new(MockPasswordReaderFail)

type MockPasswordReaderSuccess struct{}

func (mpr *MockPasswordReaderSuccess) ReadPassword() (string, error) {
	return utils.TestPassword, nil
}

type MockPasswordReaderFail struct{}

func (mpr *MockPasswordReaderFail) ReadPassword() (string, error) {
	return "", errors.New("Read password failed")
}

func TestParseURL(t *testing.T) {
	service := NewSambaService(MockPRSuccess)
	curUser, err := user.Current()
	assert.Nil(t, err)

	tests := []struct {
		name        string
		expectErr   bool
		expectProps Properties
	}{
		{
			name: "expect happy path default port",
			expectProps: Properties{
				Url:       "smb://some.test.server/sharename/and/a/file/path.txt",
				Host:      "some.test.server",
				Port:      "445",
				User:      curUser.Username,
				ShareName: "sharename",
				FilePath:  "and/a/file/path.txt",
			},
		},
		{
			name: "expect happy path with username, password, port",
			expectProps: Properties{
				Url:       "smb://test-user:test-pwd@some.test.server:1212/sharename/and/a/file/path.txt",
				Host:      "some.test.server",
				Port:      "1212",
				User:      "test-user",
				Password:  "test-pwd",
				ShareName: "sharename",
				FilePath:  "and/a/file/path.txt",
			},
		},
		{
			name: "expect happy path with domain, username, and no password",
			expectProps: Properties{
				Url:       "smb://test-domain;test-user@some.test.server/sharename/and/a/file/path.txt",
				Host:      "some.test.server",
				Port:      "445",
				Domain:    "test-domain",
				User:      "test-user",
				ShareName: "sharename",
				FilePath:  "and/a/file/path.txt",
			},
		},
		{
			name:      "expect error on bad scheme",
			expectErr: true,
			expectProps: Properties{
				Url: "://some.test.server/sharename/and/a/file/path.txt",
			},
		},
		{
			name:      "expect error on unsupported scheme",
			expectErr: true,
			expectProps: Properties{
				Url: "whatisthis://some.test.server/sharename/and/a/file/path.txt",
			},
		},
		{
			name:      "expect error on missing host",
			expectErr: true,
			expectProps: Properties{
				Url: "smb:///sharename/and/a/file/path.txt",
			},
		},
		{
			name:      "expect error on missing file path",
			expectErr: true,
			expectProps: Properties{
				Url:  "smb://some.test.server/sharename",
				Host: "some.test.server",
				Port: "445",
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p, err := service.ParseUrl(tc.expectProps.Url)
			assert.Equal(t, tc.expectErr, err != nil)
			assert.Equal(t, tc.expectProps, p)
		})
	}

	t.Run("expect success for password input", func(t *testing.T) {
		p, err := service.ParseUrl("smb://test-user:*@some.test.server:1212/sharename/and/a/file/path.txt")
		assert.Nil(t, err)
		assert.Equal(t, utils.TestPassword, p.Password)
	})
}
