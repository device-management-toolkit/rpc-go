/*********************************************************************
 * Copyright (c) Intel Corporation 2024
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/

package local

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/open-amt-cloud-toolkit/go-wsman-messages/v2/pkg/wsman/amt/publickey"
	"github.com/open-amt-cloud-toolkit/go-wsman-messages/v2/pkg/wsman/cim/wifi"
	"github.com/open-amt-cloud-toolkit/go-wsman-messages/v2/pkg/wsman/ips/ieee8021x"
	"github.com/open-amt-cloud-toolkit/rpc-go/v2/internal/config"
	"github.com/open-amt-cloud-toolkit/rpc-go/v2/internal/flags"
	"github.com/open-amt-cloud-toolkit/rpc-go/v2/pkg/utils"
	"github.com/stretchr/testify/assert"
)

var wifiCfgWPA = config.WifiConfig{
	ProfileName:          "wifiWPA",
	SSID:                 "ssid",
	Priority:             1,
	AuthenticationMethod: int(wifi.AuthenticationMethodWPAPSK),
	EncryptionMethod:     int(wifi.EncryptionMethod_CCMP),
	PskPassphrase:        "wifiWPAPassPhrase",
	Ieee8021xProfileName: "",
}

var wifiCfgWPA2 = config.WifiConfig{
	ProfileName:          "wifiWPA2",
	SSID:                 "ssid",
	Priority:             2,
	AuthenticationMethod: int(wifi.AuthenticationMethodWPA2PSK),
	EncryptionMethod:     int(wifi.EncryptionMethod_CCMP),
	PskPassphrase:        "wifiWPAPassPhrase",
	Ieee8021xProfileName: "",
}

var wifiCfgWPA8021xEAPTLS = config.WifiConfig{
	ProfileName:          "wifiWPA28021x",
	SSID:                 "ssid",
	Priority:             2,
	AuthenticationMethod: int(wifi.AuthenticationMethodWPAIEEE8021x),
	EncryptionMethod:     int(wifi.EncryptionMethod_CCMP),
	PskPassphrase:        "",
	Ieee8021xProfileName: "ieee8021xCfgEAPTLS",
}

var ieee8021xCfgEAPTLS = config.Ieee8021xConfig{
	ProfileName:            "ieee8021xCfgEAPTLS",
	Username:               "username",
	Password:               "",
	AuthenticationProtocol: int(ieee8021x.AuthenticationProtocolEAPTLS),
	ClientCert:             "clientCert",
	CACert:                 "caCert",
	PrivateKey:             "privateKey",
}

var errTestError = errors.New("test error")

func TestAddWifiSettings(t *testing.T) {
	f := &flags.Flags{}
	f.LocalConfig.WifiConfigs = append(f.LocalConfig.WifiConfigs, wifiCfgWPA)

	t.Run("expect success when AddWifiSettings", func(t *testing.T) {
		lps := setupService(f)
		err := lps.AddWifiSettings()
		assert.NoError(t, err)
	})
	t.Run("expect error failed wifi port", func(t *testing.T) {
		errEnableWiFi = errTestError
		lps := setupService(f)
		err := lps.AddWifiSettings()
		assert.Error(t, err)

		errEnableWiFi = nil
	})
}

func TestProcessWifiConfigs(t *testing.T) {
	f := &flags.Flags{}
	f.LocalConfig.WifiConfigs = append(f.LocalConfig.WifiConfigs, wifiCfgWPA)

	t.Run("expect success processing wifi configs", func(t *testing.T) {
		lps := setupService(f)
		err := lps.ProcessWifiConfigs()
		assert.NoError(t, err)
	})
	t.Run("expect warning processing 2 wifi configs with 1 bad-name", func(t *testing.T) {
		f.LocalConfig.WifiConfigs = append(f.LocalConfig.WifiConfigs, wifiCfgWPA2)
		f.LocalConfig.WifiConfigs[1].ProfileName = "bad-name"
		lps := setupService(f)
		err := lps.ProcessWifiConfigs()
		assert.Equal(t, utils.WifiConfigurationWithWarnings, err)
	})
}

func TestProcessWifiConfig(t *testing.T) {
	f := &flags.Flags{}

	t.Run("expect success when handling ieee8021x config", func(t *testing.T) {
		orig := wifiCfgWPA8021xEAPTLS.AuthenticationMethod
		wifiCfgWPA8021xEAPTLS.AuthenticationMethod = int(wifi.AuthenticationMethodWPAIEEE8021x)
		f.LocalConfig.Ieee8021xConfigs = []config.Ieee8021xConfig{
			ieee8021xCfgEAPTLS,
		}
		lps := setupService(f)
		errGetPublicPrivateKeyPairs = nil
		err := lps.ProcessWifiConfig(&wifiCfgWPA8021xEAPTLS)
		assert.NoError(t, err)

		wifiCfgWPA8021xEAPTLS.AuthenticationMethod = orig
	})
	t.Run("expect success when handling non-ieee8021x config", func(t *testing.T) {
		lps := setupService(f)
		err := lps.ProcessWifiConfig(&wifiCfgWPA2)
		assert.NoError(t, err)
	})
}

func TestEnableWifiErrors(t *testing.T) {
	f := &flags.Flags{}

	t.Run("expect success for EnableWifi", func(t *testing.T) {
		lps := setupService(f)
		err := lps.EnableWifiPort(false)
		assert.NoError(t, err)
	})
	t.Run("expect failure for EnableWifi", func(t *testing.T) {
		errEnableWiFi = errTestError
		lps := setupService(f)
		err := lps.EnableWifiPort(true)
		assert.Error(t, err)

		errEnableWiFi = nil
	})
}

func TestSetIeee8021xConfigWithEA(t *testing.T) {
	tests := []struct {
		name               string
		setupMocks         func(*MockWSMAN)
		mockauthResponse   AuthResponse
		mockconfigResponse EAProfile
		mockauthError      bool
		mockconfigError    bool
		expectError        bool
	}{
		{
			name: "Successful Wifi configuration",
			setupMocks: func(mock *MockWSMAN) {
				mockGenKeyPairErr = nil
				mockGenKeyPairReturnValue = 0
				mockGenKeyPairSelectors = []publickey.SelectorResponse{{Name: "", Text: "keyHandle"}}
				errAddClientCert = nil
				PublicPrivateKeyPairResponse = publicPrivateKeyPair
				mockCreateTLSCredentialContextErr = nil
				errGetPublicPrivateKeyPairs = nil
			},
			mockauthResponse: AuthResponse{Token: "someToken"},
			mockconfigResponse: EAProfile{
				NodeID:       "someID",
				Domain:       "someDomain",
				ReqID:        "someReqID",
				AuthProtocol: 0,

				OSName:  "win11",
				DevName: "someDevName",
				Icon:    1,
				Ver:     "someVer",
				Response: Response{
					CSR:           "someCSR",
					KeyInstanceId: "someKeyInstanceID",
					AuthProtocol:  0,
					Certificate:   "someCertificate",
					Domain:        "someDomain",
					Username:      "someUsername",
				},
			},
			expectError: false,
		},
		{
			name:          "Failed to get auth token",
			setupMocks:    func(mock *MockWSMAN) {},
			mockauthError: true,
			expectError:   true,
		},
		{
			name:            "Failed to make request to EA",
			setupMocks:      func(mock *MockWSMAN) {},
			mockauthError:   false,
			mockconfigError: true,
			expectError:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			service, _, mockWsman := setupProvisioningService()
			tt.setupMocks(mockWsman)

			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if strings.HasPrefix(r.URL.Path, "/api/authenticate/") {
					if tt.mockauthError {
						w.WriteHeader(http.StatusInternalServerError)
					} else {
						json.NewEncoder(w).Encode(tt.mockauthResponse)
					}
				} else if strings.HasPrefix(r.URL.Path, "/api/configure/") {
					if tt.expectError {
						w.WriteHeader(http.StatusInternalServerError)
					} else {
						json.NewEncoder(w).Encode(tt.mockconfigResponse)
					}
				} else {
					w.WriteHeader(http.StatusNotFound)
				}
			}))

			service.flags.LocalConfig.EnterpriseAssistant.EAAddress = server.URL
			service.flags.LocalConfig.EnterpriseAssistant.EAUsername = "user"
			service.flags.LocalConfig.EnterpriseAssistant.EAPassword = "pass"
			service.flags.LocalConfig.Ieee8021xConfigs = []config.Ieee8021xConfig{
				ieee8021xCfgEAPTLS,
			}

			ieee8021xConfig, _ := service.checkForIeee8021xConfig(&wifiCfgWPA8021xEAPTLS)

			_, err := service.setIeee8021xConfigWithEA(ieee8021xConfig)

			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
			// Clean up
			server.Close()
		})
	}
}
