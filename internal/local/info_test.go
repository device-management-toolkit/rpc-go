/*********************************************************************
 * Copyright (c) Intel Corporation 2024
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/

package local

import (
	"errors"
	"net"
	"testing"

	"github.com/open-amt-cloud-toolkit/go-wsman-messages/v2/pkg/wsman/amt/publickey"
	"github.com/open-amt-cloud-toolkit/rpc-go/v2/internal/flags"
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

func TestDisplayAMTInfo(t *testing.T) {
	defaultFlags := flags.AmtInfoFlags{
		Ver:      true,
		Bld:      true,
		Sku:      true,
		UUID:     true,
		Mode:     true,
		DNS:      true,
		Ras:      true,
		Lan:      true,
		Hostname: true,
		OpState:  true,
	}

	t.Run("returns Success on happy path", func(t *testing.T) {
		f := flags.NewFlags(nil, MockPRSuccess)
		f.AmtInfo = defaultFlags
		lps := setupService(f)
		err := lps.DisplayAMTInfo()
		assert.NoError(t, err)
		assert.Equal(t, nil, err)
	})

	t.Run("returns Success with json output", func(t *testing.T) {
		f := flags.NewFlags(nil, MockPRSuccess)
		f.AmtInfo = defaultFlags
		f.JsonOutput = true
		lps := setupService(f)
		err := lps.DisplayAMTInfo()
		assert.NoError(t, err)
		assert.Equal(t, nil, err)
	})

	t.Run("returns Success with certs", func(t *testing.T) {
		f := flags.NewFlags(nil, MockPRSuccess)
		f.AmtInfo.Cert = true
		f.AmtInfo.UserCert = true
		f.Password = "testPassword"
		mockCertHashes = mockCertHashesDefault
		pullEnvelope := publickey.PullResponse{}
		pullEnvelope.PublicKeyCertificateItems = []publickey.PublicKeyCertificateResponse{
			mpsCert,
			clientCert,
			caCert,
		}
		lps := setupService(f)
		err := lps.DisplayAMTInfo()
		assert.NoError(t, err)
		assert.Equal(t, nil, err)
	})

	t.Run("returns Success but logs errors on error conditions", func(t *testing.T) {
		mockUUIDErr = errMockStandard
		mockVersionDataErr = errMockStandard
		mockControlModeErr = errMockStandard
		mockDNSSuffixErr = errMockStandard
		mockOSDNSSuffixErr = errMockStandard
		mockRemoteAcessConnectionStatusErr = errMockStandard
		mockLANInterfaceSettingsErr = errMockStandard
		mockCertHashesErr = errMockStandard

		f := flags.NewFlags(nil, MockPRSuccess)
		f.AmtInfo = defaultFlags
		f.JsonOutput = true

		lps := setupService(f)
		err := lps.DisplayAMTInfo()
		assert.NoError(t, err)
		assert.Equal(t, nil, err)

		f.JsonOutput = false

		mockUUIDErr = nil
		mockVersionDataErr = nil
		mockControlModeErr = nil
		mockDNSSuffixErr = nil
		mockOSDNSSuffixErr = nil
		mockRemoteAcessConnectionStatusErr = nil
		mockLANInterfaceSettingsErr = nil
		mockCertHashesErr = nil
	})

	t.Run("resets UserCert on GetControlMode failure", func(t *testing.T) {
		f := flags.NewFlags(nil, MockPRSuccess)
		f.AmtInfo.UserCert = true
		mockControlModeErr = errMockStandard
		lps := setupService(f)
		err := lps.DisplayAMTInfo()
		assert.Equal(t, nil, err)
		assert.False(t, f.AmtInfo.UserCert)

		mockControlModeErr = nil
	})
	t.Run("resets UserCert when control mode is preprovisioning", func(t *testing.T) {
		f := flags.NewFlags(nil, MockPRSuccess)
		f.AmtInfo.UserCert = true
		orig := mockControlMode
		mockControlMode = 0
		lps := setupService(f)
		err := lps.DisplayAMTInfo()
		assert.Equal(t, nil, err)
		assert.False(t, f.AmtInfo.UserCert)

		mockControlMode = orig
	})
	t.Run("returns MissingOrIncorrectPassword on no password input from user", func(t *testing.T) {
		f := flags.NewFlags(nil, MockPRFail)
		f.AmtInfo.UserCert = true
		orig := mockControlMode
		mockControlMode = 2
		lps := setupService(f)
		err := lps.DisplayAMTInfo()
		assert.Equal(t, utils.MissingOrIncorrectPassword, err)
		assert.True(t, f.AmtInfo.UserCert)

		mockControlMode = orig
	})
}

func TestDecodeAMT(t *testing.T) {
	testCases := []struct {
		version string
		SKU     string
		want    string
	}{
		{"200", "0", "Invalid AMT version format"},
		{"ab.c", "0", "Invalid AMT version"},
		{"2.0.0", "0", "AMT + ASF + iQST"},
		{"2.1.0", "1", "ASF + iQST"},
		{"2.2.0", "2", "iQST"},
		{"1.1.0", "3", "Unknown"},
		{"3.0.0", "008", "Invalid SKU"},
		{"3.0.0", "8", "AMT"},
		{"4.1.0", "2", "iQST "},
		{"4.0.0", "4", "ASF "},
		{"5.0.0", "288", "TPM Home IT "},
		{"5.0.0", "1088", "WOX "},
		{"5.0.0", "38", "iQST ASF TPM "},
		{"5.0.0", "4", "ASF "},
		{"6.0.0", "2", "iQST "},
		{"7.0.0", "36864", "L3 Mgt Upgrade"},
		{"8.0.0", "24584", "AMT Pro AT-p Corporate "},
		{"10.0.0", "8", "AMT Pro "},
		{"11.0.0", "16392", "AMT Pro Corporate "},
		{"15.0.42", "16392", "AMT Pro Corporate "},
		{"16.1.25", "16400", "Intel Standard Manageability Corporate "},
	}

	for _, tc := range testCases {
		got := DecodeAMT(tc.version, tc.SKU)
		if got != tc.want {
			t.Errorf("DecodeAMT(%q, %q) = %v; want %v", tc.version, tc.SKU, got, tc.want)
		}
	}
}

func TestGetMajorVersion(t *testing.T) {
	testCases := []struct {
		version string
		want    int
		wantErr bool
	}{
		{"1.2.3", 1, false},
		{"11.8.55", 11, false},
		{"12.5.2", 12, false},
		{"16.1.25", 16, false},
		{"18.2.10", 18, false},
		{"", 0, true},
		{"abc", 0, true},
		{"1", 0, true},
		{"1.2.3.4.5", 1, false},
	}

	for _, tc := range testCases {
		got, err := GetMajorVersion(tc.version)

		if (err != nil) != tc.wantErr {
			t.Errorf("GetMajorVersion(%q) error = %v, wantErr %v", tc.version, err, tc.wantErr)
			continue
		}

		if !tc.wantErr && got != tc.want {
			t.Errorf("GetMajorVersion(%q) = %v; want %v", tc.version, got, tc.want)
		}
	}
}

var testNetEnumerator1 = flags.NetEnumerator{
	Interfaces: func() ([]net.Interface, error) {
		return []net.Interface{
			{
				Index: 0, MTU: 1200, Name: "ethTest01",
				HardwareAddr: []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05},
				Flags:        1,
			},
		}, nil
	},
	InterfaceAddrs: func(i *net.Interface) ([]net.Addr, error) {
		if i.Name == "errTest01" {
			return nil, errors.New("test message")
		} else {
			return []net.Addr{
				&net.IPNet{
					IP:   net.ParseIP("127.0.0.1"),
					Mask: net.CIDRMask(8, 32),
				},
				&net.IPNet{
					IP:   net.ParseIP("192.168.1.1"),
					Mask: net.CIDRMask(24, 32),
				},
			}, nil
		}
	},
}

var testNetEnumerator2 = flags.NetEnumerator{
	Interfaces: func() ([]net.Interface, error) {
		return []net.Interface{
			{
				Index: 0, MTU: 1200, Name: "errTest01",
				HardwareAddr: []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05},
				Flags:        1,
			},
		}, nil
	},
	InterfaceAddrs: func(i *net.Interface) ([]net.Addr, error) {
		if i.Name == "errTest01" {
			return nil, errors.New("test message")
		} else {
			return []net.Addr{
				&net.IPNet{
					IP:   net.ParseIP("127.0.0.1"),
					Mask: net.CIDRMask(8, 32),
				},
				&net.IPNet{
					IP:   net.ParseIP("192.168.1.1"),
					Mask: net.CIDRMask(24, 32),
				},
			}, nil
		}
	},
}

func TestGetOSIPAddress(t *testing.T) {
	t.Run("Valid MAC address", func(t *testing.T) {
		osIpAddress, err := GetOSIPAddress("00:01:02:03:04:05", testNetEnumerator1)
		assert.NoError(t, err)
		assert.Equal(t, "192.168.1.1", osIpAddress)
	})

	t.Run("Zero MAC address", func(t *testing.T) {
		osIpAddress, err := GetOSIPAddress("00:00:00:00:00:00", testNetEnumerator1)
		assert.NoError(t, err)
		assert.Equal(t, "0.0.0.0", osIpAddress)
	})

	t.Run("net interface fail", func(t *testing.T) {
		osIpAddress, err := GetOSIPAddress("00:01:02:03:04:05", testNetEnumerator2)
		assert.Equal(t, "0.0.0.0", osIpAddress)
		assert.Equal(t, errors.New("Failed to get interface addresses"), err)
	})

	t.Run("no matching mac address to map into os ipaddress", func(t *testing.T) {
		osIpAddress, err := GetOSIPAddress("00:11:22:33:44:55", testNetEnumerator1)
		assert.Equal(t, "Not Found", osIpAddress)
		assert.NoError(t, err)
	})
}
