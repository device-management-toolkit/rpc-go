/*********************************************************************
 * Copyright (c) Intel Corporation 2026
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/

package configure

import (
	"testing"

	"github.com/device-management-toolkit/go-wsman-messages/v2/pkg/wsman/amt/environmentdetection"
	"github.com/device-management-toolkit/go-wsman-messages/v2/pkg/wsman/amt/managementpresence"
	"github.com/device-management-toolkit/go-wsman-messages/v2/pkg/wsman/amt/remoteaccess"
	"github.com/device-management-toolkit/rpc-go/v2/internal/commands"
	mock "github.com/device-management-toolkit/rpc-go/v2/internal/mocks"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

// TestCIRACmd_Run_TooFewRemoteAccessPolicies pins that firmware returning
// fewer than the two policies just added fails with an error instead of a
// panic, before any policy is changed.
func TestCIRACmd_Run_TooFewRemoteAccessPolicies(t *testing.T) {
	for _, count := range []int{0, 1} {
		t.Run(map[int]string{0: "no policy", 1: "one policy"}[count], func(t *testing.T) {
			ctrl := gomock.NewController(t)
			mockWSMAN := mock.NewMockWSMANer(ctrl)

			cmd := &CIRACmd{
				ConfigureBaseCmd: ConfigureBaseCmd{
					AMTBaseCmd: commands.AMTBaseCmd{ControlMode: 1, WSMan: mockWSMAN},
				},
				MPSPassword:          "mps123",
				MPSAddress:           "mps.example.com",
				MPSCert:              "test-cert",
				EnvironmentDetection: []string{"example.com"},
			}

			mockWSMAN.EXPECT().GetRemoteAccessPolicies().Return([]remoteaccess.RemoteAccessPolicyAppliesToMPSResponse{}, nil)
			mockWSMAN.EXPECT().GetMPSSAP().Return([]managementpresence.ManagementRemoteResponse{}, nil)
			mockWSMAN.EXPECT().AddTrustedRootCert("test-cert").Return("cert-handle", nil)
			mockWSMAN.EXPECT().AddMPS("mps123", "mps.example.com", 4433).Return(remoteaccess.AddMpServerResponse{}, nil)
			mockWSMAN.EXPECT().GetMPSSAP().Return([]managementpresence.ManagementRemoteResponse{{Name: "test-mps"}}, nil)
			mockWSMAN.EXPECT().AddRemoteAccessPolicyRule(remoteaccess.Trigger(2), "test-mps").Return(remoteaccess.AddRemoteAccessPolicyRuleResponse{}, nil)
			mockWSMAN.EXPECT().AddRemoteAccessPolicyRule(remoteaccess.Trigger(0), "test-mps").Return(remoteaccess.AddRemoteAccessPolicyRuleResponse{}, nil)
			mockWSMAN.EXPECT().GetRemoteAccessPolicies().Return(make([]remoteaccess.RemoteAccessPolicyAppliesToMPSResponse, count), nil)
			mockWSMAN.EXPECT().PutRemoteAccessPolicyAppliesToMPS(gomock.Any()).Times(0)
			mockWSMAN.EXPECT().GetEnvironmentDetectionSettings().Return(environmentdetection.EnvironmentDetectionSettingDataResponse{}, nil).AnyTimes()

			var err error

			require.NotPanics(t, func() { err = cmd.Run(&commands.Context{AMTPassword: "test-pass"}) })
			require.EqualError(t, err, "failed to get remote access policies: expected 2 policies, got "+[]string{"0", "1"}[count])
		})
	}
}
