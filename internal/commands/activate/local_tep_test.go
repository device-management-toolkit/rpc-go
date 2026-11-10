/*********************************************************************
 * Copyright (c) Intel Corporation 2026
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/
package activate

import (
	"encoding/base64"
	"errors"
	"testing"

	"github.com/device-management-toolkit/go-wsman-messages/v2/pkg/wsman/amt/general"
	"github.com/device-management-toolkit/go-wsman-messages/v2/pkg/wsman/ips/hostbasedsetup"
	"github.com/device-management-toolkit/rpc-go/v2/internal/commands"
	mock "github.com/device-management-toolkit/rpc-go/v2/internal/mocks"
	"github.com/device-management-toolkit/rpc-go/v2/pkg/amt"
	"github.com/device-management-toolkit/rpc-go/v2/pkg/mkhi"
	"github.com/device-management-toolkit/rpc-go/v2/pkg/pthi"
	"github.com/device-management-toolkit/rpc-go/v2/pkg/upid"
	"github.com/device-management-toolkit/rpc-go/v2/pkg/utils"
	log "github.com/sirupsen/logrus"
	logtest "github.com/sirupsen/logrus/hooks/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

const tepTestCertPassword = "cert-password"

// expectTEPVoucher sets up a TEP-capable CSME (version 21) whose AMT feature
// voucher is in the given state.
func expectTEPVoucher(mockAMT *mock.MockInterface, status upid.TEPOwnershipStatus) {
	mockAMT.EXPECT().GetVersionDataFromME("AMT", gomock.Any()).Return("21.0.10", nil)
	mockAMT.EXPECT().GetFWCapabilities().Return(mkhi.FWCapsTEP, nil)
	mockAMT.EXPECT().TEPGetVoucherStateByFeature(upid.TEPFeatureAMT).Return(
		&upid.TEPVoucherState{Context: upid.TEPOwnershipContext{OwnershipStatus: status}}, nil)
}

// expectHostBasedSetup sets up the WSMAN calls of a legacy ACM activation up
// to HostBasedSetupServiceAdmin, which returns setupErr.
func expectHostBasedSetup(mockWSMAN *mock.MockWSMANer, setupErr error) {
	var settings general.Response

	settings.Body.GetResponse.DigestRealm = "Digest:TEST"

	var setupService hostbasedsetup.Response

	setupService.Body.GetResponse.ConfigurationNonce = base64.StdEncoding.EncodeToString([]byte("0123456789abcdef0123"))

	mockWSMAN.EXPECT().GetGeneralSettings().Return(settings, nil)
	mockWSMAN.EXPECT().GetHostBasedSetupService().Return(setupService, nil)
	mockWSMAN.EXPECT().AddNextCertInChain(gomock.Any(), gomock.Any(), gomock.Any()).Return(hostbasedsetup.Response{}, nil).Times(2)
	mockWSMAN.EXPECT().HostBasedSetupServiceAdmin(gomock.Any(), "Digest:TEST", gomock.Any(), gomock.Any(), false).Return(hostbasedsetup.Response{}, setupErr)
}

func newTEPTestService(t *testing.T, mockAMT amt.Interface, mockWSMAN *mock.MockWSMANer) *LocalActivationService {
	t.Helper()

	return &LocalActivationService{
		amtCommand: mockAMT,
		wsman:      mockWSMAN,
		config: LocalActivationConfig{
			Mode:                ModeACM,
			AMTPassword:         utils.TestPassword,
			ProvisioningCert:    generateTestPFXBase64(t, tepTestCertPassword),
			ProvisioningCertPwd: tepTestCertPassword,
		},
		context: &commands.Context{},
	}
}

// With an active TEP voucher for AMT, CSME validates the provisioning
// certificate against the voucher's owner credential. rpc-go must not reject
// the certificate because its root is missing from AMT's trusted root hashes.
func TestActivateACMLegacy_TEPVoucher_LeavesCertValidationToCSME(t *testing.T) {
	ctrl := gomock.NewController(t)
	mockAMT := mock.NewMockInterface(ctrl)
	mockWSMAN := mock.NewMockWSMANer(ctrl)

	expectTEPVoucher(mockAMT, upid.TEPOwnershipActive)
	// No GetCertificateHashes expectation: the root-hash check must not run.
	expectHostBasedSetup(mockWSMAN, nil)

	err := newTEPTestService(t, mockAMT, mockWSMAN).activateACMLegacy(nil)
	require.NoError(t, err)
}

// An expired or suspended voucher still makes CSME the judge, so the user gets
// CSME's TEP reason instead of rpc-go's generic root-hash error.
func TestActivateACMLegacy_TEPVoucherNotActive_StillLeavesCertValidationToCSME(t *testing.T) {
	for _, status := range []upid.TEPOwnershipStatus{upid.TEPOwnershipExpired, upid.TEPOwnershipSuspended, upid.TEPOwnershipUpdate} {
		t.Run(status.String(), func(t *testing.T) {
			ctrl := gomock.NewController(t)
			mockAMT := mock.NewMockInterface(ctrl)
			mockWSMAN := mock.NewMockWSMANer(ctrl)

			expectTEPVoucher(mockAMT, status)
			expectHostBasedSetup(mockWSMAN, nil)

			err := newTEPTestService(t, mockAMT, mockWSMAN).activateACMLegacy(nil)
			require.NoError(t, err)
		})
	}
}

// When CSME rejects the certificate in a TEP flow, the error carries the
// reason from the CSME provisioning log.
func TestActivateACMLegacy_TEPVoucher_CSMERejection_ReportsProvisioningLogReason(t *testing.T) {
	ctrl := gomock.NewController(t)
	mockAMT := mock.NewMockInterface(ctrl)
	mockWSMAN := mock.NewMockWSMANer(ctrl)

	expectTEPVoucher(mockAMT, upid.TEPOwnershipActive)
	expectHostBasedSetup(mockWSMAN, errors.New("400 Bad Request"))
	mockAMT.EXPECT().Initialize().Return(nil)
	mockAMT.EXPECT().GetControlMode().Return(0, nil)
	mockAMT.EXPECT().Close().Return(nil).AnyTimes()
	mockAMT.EXPECT().GetProvisioningLog().Return(pthi.ProvisioningLog{AcmProvisioningStatus: pthi.PROV_RES_TEP_HASH_MISMATCH}, nil)

	err := newTEPTestService(t, mockAMT, mockWSMAN).activateACMLegacy(nil)
	require.Error(t, err)

	var customErr utils.CustomError
	require.ErrorAs(t, err, &customErr)
	assert.Equal(t, utils.ActivationFailedControlMode.Code, customErr.Code)
	assert.Contains(t, customErr.Details, "TEP owner credential hash mismatch")
}

// Without a usable voucher the traditional flow is unchanged: rpc-go checks
// the root against AMT's trusted hashes before sending anything to AMT.
func TestActivateACMLegacy_NoTEPVoucher_ChecksRootHash(t *testing.T) {
	tests := []struct {
		name   string
		expect func(*mock.MockInterface)
	}{
		{
			name: "CSME older than TEP",
			expect: func(m *mock.MockInterface) {
				m.EXPECT().GetVersionDataFromME("AMT", gomock.Any()).Return("16.1.35", nil)
			},
		},
		{
			name: "AMT version unreadable",
			expect: func(m *mock.MockInterface) {
				m.EXPECT().GetVersionDataFromME("AMT", gomock.Any()).Return("", errors.New("heci timeout"))
			},
		},
		{
			name: "TEP not in firmware capabilities",
			expect: func(m *mock.MockInterface) {
				m.EXPECT().GetVersionDataFromME("AMT", gomock.Any()).Return("21.0.10", nil)
				m.EXPECT().GetFWCapabilities().Return(mkhi.FWCapabilities(0), nil)
			},
		},
		{
			name: "no voucher installed",
			expect: func(m *mock.MockInterface) {
				m.EXPECT().GetVersionDataFromME("AMT", gomock.Any()).Return("21.0.10", nil)
				m.EXPECT().GetFWCapabilities().Return(mkhi.FWCapsTEP, nil)
				m.EXPECT().TEPGetVoucherStateByFeature(upid.TEPFeatureAMT).Return(nil, upid.ErrTEPInvalidVoucher)
			},
		},
		{
			name: "voucher only requested",
			expect: func(m *mock.MockInterface) {
				expectTEPVoucher(m, upid.TEPOwnershipRequested)
			},
		},
		{
			name: "voucher state unreadable",
			expect: func(m *mock.MockInterface) {
				m.EXPECT().GetVersionDataFromME("AMT", gomock.Any()).Return("21.0.10", nil)
				m.EXPECT().GetFWCapabilities().Return(mkhi.FWCapsTEP, nil)
				m.EXPECT().TEPGetVoucherStateByFeature(upid.TEPFeatureAMT).Return(nil, errors.New("heci timeout"))
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			mockAMT := mock.NewMockInterface(ctrl)
			mockWSMAN := mock.NewMockWSMANer(ctrl)

			tt.expect(mockAMT)
			mockAMT.EXPECT().GetCertificateHashes().Return([]amt.CertHashEntry{{Algorithm: "SHA384", Hash: "not-the-root"}}, nil)
			// No WSMAN expectations: nothing may be sent to AMT.

			err := newTEPTestService(t, mockAMT, mockWSMAN).activateACMLegacy(nil)
			assert.Equal(t, utils.ActivationFailedProvCertNoMatch, err)
		})
	}
}

// A failed read on a TEP-capable device means the voucher could not be
// checked, so the root-hash fallback may reject a certificate CSME would
// accept (error 128). That must show at warn level; a device that simply has
// no voucher stays quiet.
func TestTEPVoucherInstalled_ReadFailureWarns(t *testing.T) {
	tests := []struct {
		name     string
		expect   func(*mock.MockInterface)
		wantWarn bool
	}{
		{
			name: "voucher state unreadable",
			expect: func(m *mock.MockInterface) {
				m.EXPECT().GetVersionDataFromME("AMT", gomock.Any()).Return("21.0.10", nil)
				m.EXPECT().GetFWCapabilities().Return(mkhi.FWCapsTEP, nil)
				m.EXPECT().TEPGetVoucherStateByFeature(upid.TEPFeatureAMT).Return(nil, errors.New("heci timeout"))
			},
			wantWarn: true,
		},
		{
			name: "firmware capabilities unreadable",
			expect: func(m *mock.MockInterface) {
				m.EXPECT().GetVersionDataFromME("AMT", gomock.Any()).Return("21.0.10", nil)
				m.EXPECT().GetFWCapabilities().Return(mkhi.FWCapabilities(0), errors.New("heci timeout"))
			},
			wantWarn: true,
		},
		{
			name: "no voucher installed",
			expect: func(m *mock.MockInterface) {
				m.EXPECT().GetVersionDataFromME("AMT", gomock.Any()).Return("21.0.10", nil)
				m.EXPECT().GetFWCapabilities().Return(mkhi.FWCapsTEP, nil)
				m.EXPECT().TEPGetVoucherStateByFeature(upid.TEPFeatureAMT).Return(nil, upid.ErrTEPInvalidVoucher)
			},
			wantWarn: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hook := logtest.NewGlobal()
			defer hook.Reset()

			ctrl := gomock.NewController(t)
			mockAMT := mock.NewMockInterface(ctrl)
			tt.expect(mockAMT)

			service := &LocalActivationService{amtCommand: mockAMT}
			assert.False(t, service.tepVoucherInstalled())

			warned := false

			for _, entry := range hook.AllEntries() {
				if entry.Level == log.WarnLevel {
					warned = true
				}
			}

			assert.Equal(t, tt.wantWarn, warned)
		})
	}
}
