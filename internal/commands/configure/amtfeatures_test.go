/*********************************************************************
 * Copyright (c) Intel Corporation 2024
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/

package configure

import (
	"errors"
	"testing"

	"github.com/device-management-toolkit/go-wsman-messages/v2/pkg/wsman/amt/redirection"
	"github.com/device-management-toolkit/go-wsman-messages/v2/pkg/wsman/cim/kvm"
	"github.com/device-management-toolkit/go-wsman-messages/v2/pkg/wsman/ips/optin"
	"github.com/device-management-toolkit/rpc-go/v2/internal/commands"
	mock "github.com/device-management-toolkit/rpc-go/v2/internal/mocks"
	"github.com/device-management-toolkit/rpc-go/v2/pkg/utils"
	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"
)

func TestAMTFeaturesCmd_Structure(t *testing.T) {
	// Test that AMTFeaturesCmd has the correct structure
	cmd := &AMTFeaturesCmd{}

	// Test basic field access to ensure struct is correct
	cmd.Password = "test123"
	cmd.UserConsent = "kvm"
	cmd.KVM = true
	cmd.SOL = true
	cmd.IDER = false

	assert.Equal(t, "test123", cmd.Password)
	assert.Equal(t, "kvm", cmd.UserConsent)
	assert.Equal(t, true, cmd.KVM)
	assert.Equal(t, true, cmd.SOL)
	assert.Equal(t, false, cmd.IDER)
}

func TestAMTFeaturesCmd_Validate(t *testing.T) {
	tests := []struct {
		name        string
		cmd         AMTFeaturesCmd
		wantErr     bool
		description string
	}{
		{
			name: "password provided with KVM feature",
			cmd: AMTFeaturesCmd{
				ConfigureBaseCmd: ConfigureBaseCmd{
					AMTBaseCmd: commands.AMTBaseCmd{
						Password:    "test123",
						ControlMode: 1, // Device is activated
					},
				},
				UserConsent: "kvm",
				KVM:         true,
			},
			wantErr:     false,
			description: "should succeed when password is provided with KVM feature",
		},
		{
			name: "password provided with SOL feature",
			cmd: AMTFeaturesCmd{
				ConfigureBaseCmd: ConfigureBaseCmd{
					AMTBaseCmd: commands.AMTBaseCmd{
						Password:    "test123",
						ControlMode: 1, // Device is activated
					},
				},
				SOL: true,
			},
			wantErr:     false,
			description: "should succeed when password is provided with SOL feature",
		},
		{
			name: "password provided with IDER feature",
			cmd: AMTFeaturesCmd{
				ConfigureBaseCmd: ConfigureBaseCmd{
					AMTBaseCmd: commands.AMTBaseCmd{
						Password:    "test123",
						ControlMode: 1, // Device is activated
					},
				},
				IDER: true,
			},
			wantErr:     false,
			description: "should succeed when password is provided with IDER feature",
		},
		{
			name: "password provided with UserConsent",
			cmd: AMTFeaturesCmd{
				ConfigureBaseCmd: ConfigureBaseCmd{
					AMTBaseCmd: commands.AMTBaseCmd{
						Password:    "test123",
						ControlMode: 1, // Device is activated
					},
				},
				UserConsent: "none",
			},
			wantErr:     false,
			description: "should succeed when password is provided with UserConsent",
		},
		{
			name: "no features specified",
			cmd: AMTFeaturesCmd{
				ConfigureBaseCmd: ConfigureBaseCmd{
					AMTBaseCmd: commands.AMTBaseCmd{
						Password:    "test123",
						ControlMode: 1, // Device is activated
					},
				},
				UserConsent: "", // No value provided
				KVM:         false,
				SOL:         false,
				IDER:        false,
			},
			wantErr:     true,
			description: "should fail when no features are specified",
		},
		{
			name: "multiple features enabled",
			cmd: AMTFeaturesCmd{
				ConfigureBaseCmd: ConfigureBaseCmd{
					AMTBaseCmd: commands.AMTBaseCmd{
						Password:    "test123",
						ControlMode: 1, // Device is activated
					},
				},
				UserConsent: "all",
				KVM:         true,
				SOL:         true,
				IDER:        true,
			},
			wantErr:     false,
			description: "should succeed with multiple features enabled",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.cmd.Validate()

			if tt.wantErr {
				assert.Error(t, err, tt.description)
			} else {
				assert.NoError(t, err, tt.description)
			}
		})
	}
}

func TestAMTFeaturesCmd_Run_DeviceNotActivated(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockAMT := mock.NewMockInterface(ctrl)
	mockWSMAN := mock.NewMockWSMANer(ctrl)

	cmd := &AMTFeaturesCmd{
		ConfigureBaseCmd: ConfigureBaseCmd{
			AMTBaseCmd: commands.AMTBaseCmd{
				Password:    "test123",
				WSMan:       mockWSMAN,
				ControlMode: 0, // Set control mode to 0 (not activated)
			},
		},
		KVM: true,
	}

	ctx := &commands.Context{
		AMTCommand: mockAMT,
	}

	err := cmd.Run(ctx)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "device is not activated")
}

func TestAMTFeaturesCmd_Run_GetControlModeError(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockAMT := mock.NewMockInterface(ctrl)
	mockWSMAN := mock.NewMockWSMANer(ctrl)

	cmd := &AMTFeaturesCmd{
		ConfigureBaseCmd: ConfigureBaseCmd{
			AMTBaseCmd: commands.AMTBaseCmd{
				Password:    "test123",
				WSMan:       mockWSMAN,
				ControlMode: 0, // Set control mode to 0 (not activated)
			},
		},
		KVM: true,
	}

	ctx := &commands.Context{
		AMTCommand: mockAMT,
	}

	// With the new structure, control mode errors are handled during initialization
	// so this test now checks for device not activated error
	err := cmd.Run(ctx)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "device is not activated")
}

func TestAMTFeaturesCmd_Run_CCMMode_KVMFeature(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockAMT := mock.NewMockInterface(ctrl)
	mockWSMAN := mock.NewMockWSMANer(ctrl)

	cmd := &AMTFeaturesCmd{
		ConfigureBaseCmd: ConfigureBaseCmd{
			AMTBaseCmd: commands.AMTBaseCmd{
				Password:    "test123",
				WSMan:       mockWSMAN,
				ControlMode: 1, // Set control mode to 1 (CCM mode)
			},
		},
		KVM: true,
	}

	ctx := &commands.Context{
		AMTCommand: mockAMT,
	}

	// Mock GetRedirectionService
	redirectionResponse := redirection.Response{
		Body: redirection.Body{
			GetAndPutResponse: redirection.RedirectionResponse{
				Name:                    "Intel(r) AMT Redirection Service",
				CreationClassName:       "AMT_RedirectionService",
				SystemCreationClassName: "CIM_ComputerSystem",
				SystemName:              "Intel(r) AMT",
				ElementName:             "Intel(r) AMT Redirection Service",
			},
		},
	}
	mockWSMAN.EXPECT().GetRedirectionService().Return(redirectionResponse, nil)

	// Mock RequestRedirectionStateChange
	mockWSMAN.EXPECT().RequestRedirectionStateChange(gomock.Any()).Return(redirection.Response{}, nil)

	// Mock GetVersionDataFromME calls for ISM check
	mockAMT.EXPECT().GetVersionDataFromME("AMT", gomock.Any()).Return("11.8.50", nil)
	mockAMT.EXPECT().GetVersionDataFromME("Sku", gomock.Any()).Return("16392", nil)

	// Mock RequestKVMStateChange (since it's not ISM)
	mockWSMAN.EXPECT().RequestKVMStateChange(kvm.KVMRedirectionSAPRequestStateChangeInput(2)).Return(kvm.Response{}, nil)

	// Mock PutRedirectionState
	mockWSMAN.EXPECT().PutRedirectionState(gomock.Any()).Return(redirection.Response{}, nil)

	err := cmd.Run(ctx)
	assert.NoError(t, err)
}

func TestAMTFeaturesCmd_Run_ACMMode_WithUserConsent(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockAMT := mock.NewMockInterface(ctrl)
	mockWSMAN := mock.NewMockWSMANer(ctrl)

	cmd := &AMTFeaturesCmd{
		ConfigureBaseCmd: ConfigureBaseCmd{
			AMTBaseCmd: commands.AMTBaseCmd{
				Password:    "test123",
				WSMan:       mockWSMAN,
				ControlMode: 2, // Set control mode to 2 (ACM mode)
			},
		},
		UserConsent: "kvm",
		SOL:         true,
	}

	ctx := &commands.Context{
		AMTCommand: mockAMT,
	}

	// Mock GetRedirectionService
	redirectionResponse := redirection.Response{
		Body: redirection.Body{
			GetAndPutResponse: redirection.RedirectionResponse{
				Name:                    "Intel(r) AMT Redirection Service",
				CreationClassName:       "AMT_RedirectionService",
				SystemCreationClassName: "CIM_ComputerSystem",
				SystemName:              "Intel(r) AMT",
				ElementName:             "Intel(r) AMT Redirection Service",
			},
		},
	}
	mockWSMAN.EXPECT().GetRedirectionService().Return(redirectionResponse, nil)

	// Mock RequestRedirectionStateChange
	mockWSMAN.EXPECT().RequestRedirectionStateChange(gomock.Any()).Return(redirection.Response{}, nil)

	// Mock GetVersionDataFromME calls for ISM check
	mockAMT.EXPECT().GetVersionDataFromME("AMT", gomock.Any()).Return("11.8.50", nil)
	mockAMT.EXPECT().GetVersionDataFromME("Sku", gomock.Any()).Return("16392", nil)

	// Mock RequestKVMStateChange (since it's not ISM and KVM is false, it should be disabled - state 3)
	mockWSMAN.EXPECT().RequestKVMStateChange(kvm.KVMRedirectionSAPRequestStateChangeInput(3)).Return(kvm.Response{}, nil)

	// Mock PutRedirectionState
	mockWSMAN.EXPECT().PutRedirectionState(gomock.Any()).Return(redirection.Response{}, nil)

	// Mock GetIpsOptInService for ACM mode
	optInResponse := optin.Response{
		Body: optin.Body{
			GetAndPutResponse: optin.OptInServiceResponse{
				CanModifyOptInPolicy:    1,
				CreationClassName:       "IPS_OptInService",
				ElementName:             "Intel(r) AMT OptIn Service",
				Name:                    "Intel(r) AMT OptIn Service",
				OptInCodeTimeout:        120,
				OptInDisplayTimeout:     300,
				OptInRequired:           uint32(optin.OptInRequiredAll),
				OptInState:              1,
				SystemCreationClassName: "CIM_ComputerSystem",
				SystemName:              "Intel(r) AMT",
			},
		},
	}
	mockWSMAN.EXPECT().GetIpsOptInService().Return(optInResponse, nil)

	// Mock PutIpsOptInService
	mockWSMAN.EXPECT().PutIpsOptInService(gomock.Any()).Return(optin.Response{}, nil)

	err := cmd.Run(ctx)
	assert.NoError(t, err)
}

func TestAMTFeaturesCmd_Run_ISMSystem(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockAMT := mock.NewMockInterface(ctrl)
	mockWSMAN := mock.NewMockWSMANer(ctrl)

	cmd := &AMTFeaturesCmd{
		ConfigureBaseCmd: ConfigureBaseCmd{
			AMTBaseCmd: commands.AMTBaseCmd{
				Password:    "test123",
				WSMan:       mockWSMAN,
				ControlMode: 1, // Set control mode to 1 (CCM mode)
			},
		},
		KVM:  true,
		IDER: true,
	}

	ctx := &commands.Context{
		AMTCommand: mockAMT,
	}

	// Mock GetRedirectionService
	redirectionResponse := redirection.Response{
		Body: redirection.Body{
			GetAndPutResponse: redirection.RedirectionResponse{
				Name:                    "Intel(r) AMT Redirection Service",
				CreationClassName:       "AMT_RedirectionService",
				SystemCreationClassName: "CIM_ComputerSystem",
				SystemName:              "Intel(r) AMT",
				ElementName:             "Intel(r) AMT Redirection Service",
			},
		},
	}
	mockWSMAN.EXPECT().GetRedirectionService().Return(redirectionResponse, nil)

	// Mock RequestRedirectionStateChange
	mockWSMAN.EXPECT().RequestRedirectionStateChange(gomock.Any()).Return(redirection.Response{}, nil)

	// Mock GetVersionDataFromME calls for ISM check - return ISM system
	mockAMT.EXPECT().GetVersionDataFromME("AMT", gomock.Any()).Return("11.8.50", nil)
	mockAMT.EXPECT().GetVersionDataFromME("Sku", gomock.Any()).Return("16400", nil) // ISM SKU - contains Intel Standard Manageability

	// No KVM state change call expected for ISM systems

	// Mock PutRedirectionState
	mockWSMAN.EXPECT().PutRedirectionState(gomock.Any()).Return(redirection.Response{}, nil)

	err := cmd.Run(ctx)
	assert.NoError(t, err)
}

func TestAMTFeaturesCmd_Run_Errors(t *testing.T) {
	tests := []struct {
		name          string
		setupMocks    func(*mock.MockWSMANer, *mock.MockInterface)
		expectedError error
		errorContains string
	}{
		{
			name: "GetRedirectionService error",
			setupMocks: func(mockWSMAN *mock.MockWSMANer, mockAMT *mock.MockInterface) {
				mockWSMAN.EXPECT().GetRedirectionService().Return(redirection.Response{}, errors.New("redirection error"))
			},
			expectedError: utils.AMTFeaturesConfigurationFailed,
		},
		{
			name: "RequestRedirectionStateChange error",
			setupMocks: func(mockWSMAN *mock.MockWSMANer, mockAMT *mock.MockInterface) {
				redirectionResponse := redirection.Response{
					Body: redirection.Body{
						GetAndPutResponse: redirection.RedirectionResponse{
							Name: "test",
						},
					},
				}
				mockWSMAN.EXPECT().GetRedirectionService().Return(redirectionResponse, nil)
				mockWSMAN.EXPECT().RequestRedirectionStateChange(gomock.Any()).Return(redirection.Response{}, errors.New("redirection state error"))
			},
			expectedError: utils.AMTFeaturesConfigurationFailed,
		},
		{
			name: "GetVersionDataFromME AMT error",
			setupMocks: func(mockWSMAN *mock.MockWSMANer, mockAMT *mock.MockInterface) {
				redirectionResponse := redirection.Response{
					Body: redirection.Body{
						GetAndPutResponse: redirection.RedirectionResponse{
							Name: "test",
						},
					},
				}
				mockWSMAN.EXPECT().GetRedirectionService().Return(redirectionResponse, nil)
				mockWSMAN.EXPECT().RequestRedirectionStateChange(gomock.Any()).Return(redirection.Response{}, nil)
				mockAMT.EXPECT().GetVersionDataFromME("AMT", gomock.Any()).Return("", errors.New("AMT version error"))
			},
			expectedError: utils.AMTFeaturesConfigurationFailed,
		},
		{
			name: "GetVersionDataFromME Sku error",
			setupMocks: func(mockWSMAN *mock.MockWSMANer, mockAMT *mock.MockInterface) {
				redirectionResponse := redirection.Response{
					Body: redirection.Body{
						GetAndPutResponse: redirection.RedirectionResponse{
							Name: "test",
						},
					},
				}
				mockWSMAN.EXPECT().GetRedirectionService().Return(redirectionResponse, nil)
				mockWSMAN.EXPECT().RequestRedirectionStateChange(gomock.Any()).Return(redirection.Response{}, nil)
				mockAMT.EXPECT().GetVersionDataFromME("AMT", gomock.Any()).Return("11.8.50", nil)
				mockAMT.EXPECT().GetVersionDataFromME("Sku", gomock.Any()).Return("", errors.New("Sku version error"))
			},
			expectedError: utils.AMTFeaturesConfigurationFailed,
		},
		{
			name: "RequestKVMStateChange error",
			setupMocks: func(mockWSMAN *mock.MockWSMANer, mockAMT *mock.MockInterface) {
				redirectionResponse := redirection.Response{
					Body: redirection.Body{
						GetAndPutResponse: redirection.RedirectionResponse{
							Name: "test",
						},
					},
				}
				mockWSMAN.EXPECT().GetRedirectionService().Return(redirectionResponse, nil)
				mockWSMAN.EXPECT().RequestRedirectionStateChange(gomock.Any()).Return(redirection.Response{}, nil)
				mockAMT.EXPECT().GetVersionDataFromME("AMT", gomock.Any()).Return("11.8.50", nil)
				mockAMT.EXPECT().GetVersionDataFromME("Sku", gomock.Any()).Return("16392", nil)
				mockWSMAN.EXPECT().RequestKVMStateChange(gomock.Any()).Return(kvm.Response{}, errors.New("KVM state error"))
			},
			expectedError: utils.AMTFeaturesConfigurationFailed,
		},
		{
			name: "PutRedirectionState error",
			setupMocks: func(mockWSMAN *mock.MockWSMANer, mockAMT *mock.MockInterface) {
				redirectionResponse := redirection.Response{
					Body: redirection.Body{
						GetAndPutResponse: redirection.RedirectionResponse{
							Name: "test",
						},
					},
				}
				mockWSMAN.EXPECT().GetRedirectionService().Return(redirectionResponse, nil)
				mockWSMAN.EXPECT().RequestRedirectionStateChange(gomock.Any()).Return(redirection.Response{}, nil)
				mockAMT.EXPECT().GetVersionDataFromME("AMT", gomock.Any()).Return("11.8.50", nil)
				mockAMT.EXPECT().GetVersionDataFromME("Sku", gomock.Any()).Return("16392", nil)
				mockWSMAN.EXPECT().RequestKVMStateChange(gomock.Any()).Return(kvm.Response{}, nil)
				mockWSMAN.EXPECT().PutRedirectionState(gomock.Any()).Return(redirection.Response{}, errors.New("put redirection error"))
			},
			expectedError: utils.AMTFeaturesConfigurationFailed,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			mockAMT := mock.NewMockInterface(ctrl)
			mockWSMAN := mock.NewMockWSMANer(ctrl)

			cmd := &AMTFeaturesCmd{
				ConfigureBaseCmd: ConfigureBaseCmd{
					AMTBaseCmd: commands.AMTBaseCmd{
						Password:    "test123",
						WSMan:       mockWSMAN,
						ControlMode: 1, // Set control mode to 1 (activated)
					},
				},
				KVM: true,
			}

			ctx := &commands.Context{
				AMTCommand: mockAMT,
			}

			tt.setupMocks(mockWSMAN, mockAMT)

			err := cmd.Run(ctx)
			if tt.expectedError != nil {
				assert.Equal(t, tt.expectedError, err)
			} else {
				assert.Error(t, err)

				if tt.errorContains != "" {
					assert.Contains(t, err.Error(), tt.errorContains)
				}
			}
		})
	}
}
