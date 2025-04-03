package local

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/open-amt-cloud-toolkit/go-wsman-messages/v2/pkg/wsman/amt/ethernetport"
	"github.com/open-amt-cloud-toolkit/go-wsman-messages/v2/pkg/wsman/amt/publickey"
	"github.com/open-amt-cloud-toolkit/rpc-go/v2/internal/config"
	"github.com/open-amt-cloud-toolkit/rpc-go/v2/internal/flags"
	"github.com/open-amt-cloud-toolkit/rpc-go/v2/pkg/utils"
	"github.com/stretchr/testify/assert"
)

var mockauthResponse = AuthResponse{Token: "someToken"}
var mockconfigResponse = EAProfile{
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
}
var Ieee8021xConfigs = []config.Ieee8021xConfig{
	{
		ProfileName:            "testProfile",
		Username:               "exampleUserName",
		AuthenticationProtocol: 0,
		ClientCert:             "clientCert",
		CACert:                 "caCert",
		PrivateKey:             "privateKey",
	},
}

func httpServer(expectError error) (server *httptest.Server) {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/api/authenticate/") {
			if expectError != nil {
				w.WriteHeader(http.StatusInternalServerError)
			} else {
				json.NewEncoder(w).Encode(mockauthResponse)
			}
		} else if strings.HasPrefix(r.URL.Path, "/api/configure/") {
			if expectError != nil {
				w.WriteHeader(http.StatusInternalServerError)
			} else {
				json.NewEncoder(w).Encode(mockconfigResponse)
			}
		} else {
			w.WriteHeader(http.StatusNotFound)
		}
	}))
}

func TestWiredSettings(t *testing.T) {
	tests := []struct {
		name               string
		config             *config.Config
		setupMocks         func(*MockWSMAN)
		mockauthResponse   AuthResponse
		mockconfigResponse EAProfile
		mockauthError      bool
		mockconfigError    bool
		expectedErr        error
	}{
		{
			name: "Success - DHCP and IpSync",
			config: &config.Config{
				WiredConfig: config.EthernetConfig{
					DHCP:   true,
					IpSync: true,
				},
			},
			setupMocks: func(mock *MockWSMAN) {
				putEthernetResponse = ethernetport.Response{
					Body: ethernetport.Body{
						GetAndPutResponse: ethernetport.SettingsResponse{
							IpSyncEnabled: true,
							DHCPEnabled:   true,
						},
					},
				}
				errPutEthernetSettings = nil
			},
		},
		{
			name: "Success - Static and IpSync",
			config: &config.Config{
				WiredConfig: config.EthernetConfig{
					Static: true,
					IpSync: true,
				},
			},
			setupMocks: func(mock *MockWSMAN) {
				putEthernetResponse = ethernetport.Response{
					Body: ethernetport.Body{
						GetAndPutResponse: ethernetport.SettingsResponse{
							IpSyncEnabled:  true,
							SharedStaticIp: true,
						},
					},
				}
				errPutEthernetSettings = nil
			},
		},
		{
			name: "Success - Static and Info",
			config: &config.Config{
				WiredConfig: config.EthernetConfig{
					Static:     true,
					IpAddress:  "192.168.1.7",
					Subnetmask: "255.255.255.0",
					Gateway:    "192.168.1.1",
					PrimaryDNS: "8.8.8.8",
				},
			},
			setupMocks: func(mock *MockWSMAN) {
				putEthernetResponse = ethernetport.Response{
					Body: ethernetport.Body{
						GetAndPutResponse: ethernetport.SettingsResponse{
							SharedStaticIp: true,
							IPAddress:      "192.168.1.7",
							SubnetMask:     "255.255.255.0",
							DefaultGateway: "192.168.1.1",
							PrimaryDNS:     "8.8.8.8",
						},
					},
				}
				errPutEthernetSettings = nil
			},
		},
		{
			name: "Success - Static and Info and secondaryDns",
			config: &config.Config{
				WiredConfig: config.EthernetConfig{
					Static:       true,
					IpAddress:    "192.168.1.7",
					Subnetmask:   "255.255.255.0",
					Gateway:      "192.168.1.1",
					PrimaryDNS:   "8.8.8.8",
					SecondaryDNS: "4.4.4.4",
				},
			},
			setupMocks: func(mock *MockWSMAN) {
				putEthernetResponse = ethernetport.Response{
					Body: ethernetport.Body{
						GetAndPutResponse: ethernetport.SettingsResponse{
							SharedStaticIp: true,
							IPAddress:      "192.168.1.7",
							SubnetMask:     "255.255.255.0",
							DefaultGateway: "192.168.1.1",
							PrimaryDNS:     "8.8.8.8",
							SecondaryDNS:   "4.4.4.4",
						},
					},
				}
				errPutEthernetSettings = nil
			},
		},
		{
			name: "Fail - No DHCP or Static",
			config: &config.Config{
				WiredConfig: config.EthernetConfig{
					DHCP:   false,
					Static: false,
				},
			},
			setupMocks:  func(mock *MockWSMAN) {},
			expectedErr: utils.InvalidParameterCombination,
		},
		{
			name: "Fail - Static, No IpSync, Missing Info",
			config: &config.Config{
				WiredConfig: config.EthernetConfig{
					Static: true,
				},
			},
			setupMocks:  func(mock *MockWSMAN) {},
			expectedErr: utils.MissingOrIncorrectStaticIP,
		},
		{
			name: "Fail - DHCP and Info ",
			config: &config.Config{
				WiredConfig: config.EthernetConfig{
					DHCP:         true,
					IpAddress:    "192.168.1.7",
					SecondaryDNS: "4.4.4.4",
				},
			},
			setupMocks:  func(mock *MockWSMAN) {},
			expectedErr: utils.InvalidParameterCombination,
		},
		{
			name: "Fail - WSManMessage Error",
			config: &config.Config{
				WiredConfig: config.EthernetConfig{
					DHCP:   true,
					IpSync: true,
				},
			},
			setupMocks: func(mock *MockWSMAN) {
				errPutEthernetSettings = utils.WSMANMessageError
			},
			expectedErr: utils.WiredConfigurationFailed,
		},
		{
			name: "Success - 802.1x Configuration Without EA",
			config: &config.Config{
				WiredConfig: config.EthernetConfig{
					DHCP:                 true,
					IpSync:               true,
					Ieee8021xProfileName: "testProfile",
				},
				EnterpriseAssistant: config.EnterpriseAssistant{
					EAAddress:    "",
					EAUsername:   "user",
					EAPassword:   "pass",
					EAConfigured: false,
				},
				Ieee8021xConfigs: Ieee8021xConfigs,
			},
			setupMocks: func(mock *MockWSMAN) {
				errPutEthernetSettings = nil
				mockGenKeyPairErr = nil
				mockGenKeyPairReturnValue = 0
				mockGenKeyPairSelectors = []publickey.SelectorResponse{{Name: "", Text: "keyHandle"}}
				errAddClientCert = nil
				PublicPrivateKeyPairResponse = publicPrivateKeyPair
				mockCreateTLSCredentialContextErr = nil
			},
			expectedErr: nil,
		},
		{
			name: "Success - 802.1x Configuration With EA Configured",
			config: &config.Config{
				WiredConfig: config.EthernetConfig{
					DHCP:                 true,
					IpSync:               true,
					Ieee8021xProfileName: "testProfile",
				},
				EnterpriseAssistant: config.EnterpriseAssistant{
					EAAddress:    "",
					EAUsername:   "user",
					EAPassword:   "pass",
					EAConfigured: true,
				},
				Ieee8021xConfigs: Ieee8021xConfigs,
			},
			setupMocks: func(mock *MockWSMAN) {
				errPutEthernetSettings = nil
				mockGenKeyPairErr = nil
				mockGenKeyPairReturnValue = 0
				mockGenKeyPairSelectors = []publickey.SelectorResponse{{Name: "", Text: "keyHandle"}}
				errAddClientCert = nil
				PublicPrivateKeyPairResponse = publicPrivateKeyPair
				mockCreateTLSCredentialContextErr = nil
			},
			mockauthResponse:   mockauthResponse,
			mockconfigResponse: mockconfigResponse,
			expectedErr:        nil,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			flags := &flags.Flags{}
			mockAMT := new(MockAMT)
			mockWsman := new(MockWSMAN)
			tc.setupMocks(mockWsman)
			server := httpServer(tc.expectedErr)
			tc.config.EnterpriseAssistant.EAAddress = server.URL
			testService := NewProvisioningService(flags)
			testService.amtCommand = mockAMT
			testService.config = tc.config
			testService.interfacedWsmanMessage = mockWsman

			err := testService.AddEthernetSettings()
			assert.Equal(t, tc.expectedErr, err)
			// Clean up
			server.Close()
		})
	}
}

func TestAddCertsUsingEnterpriseAssistant(t *testing.T) {
	tests := []struct {
		name               string
		setupMocks         func(*MockWSMAN)
		mockauthResponse   AuthResponse
		mockconfigResponse EAProfile
		mockauthError      bool
		mockconfigError    bool
		expectError        error
	}{
		{
			name: "Successful TLS configuration",
			setupMocks: func(mock *MockWSMAN) {
				mockGenKeyPairErr = nil
				mockGenKeyPairReturnValue = 0
				mockGenKeyPairSelectors = []publickey.SelectorResponse{{Name: "", Text: "keyHandle"}}
				errAddClientCert = nil
				PublicPrivateKeyPairResponse = publicPrivateKeyPair
				mockCreateTLSCredentialContextErr = nil
			},
			mockauthResponse:   mockauthResponse,
			mockconfigResponse: mockconfigResponse,
			expectError:        nil,
		},
		{
			name:          "Failed to get auth token",
			setupMocks:    func(mock *MockWSMAN) {},
			mockauthError: true,
			expectError:   utils.Ieee8021xConfigurationFailed,
		},
		{
			name:            "Failed to make request to EA",
			setupMocks:      func(mock *MockWSMAN) {},
			mockauthError:   false,
			mockconfigError: true,
			expectError:     utils.Ieee8021xConfigurationFailed,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			service, mockWsman := setupProvisioningService()
			tt.setupMocks(mockWsman)
			server := httpServer(tt.expectError)
			service.config.EnterpriseAssistant.EAAddress = server.URL
			service.config.EnterpriseAssistant.EAUsername = "user"
			service.config.EnterpriseAssistant.EAPassword = "pass"

			var handles Handles

			handles, _, err := service.AddCertsUsingEnterpriseAssistant(Ieee8021xConfigs[0])
			if tt.expectError != nil {
				assert.Error(t, err)
			} else {
				assert.NotEmpty(t, handles.keyPairHandle)
				assert.NoError(t, err)
			}
			// Clean up
			server.Close()
		})
	}
}
