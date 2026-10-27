/*********************************************************************
 * Copyright (c) Intel Corporation 2026
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/

package commands

import (
	"bytes"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/json"
	"errors"
	"fmt"
	"testing"

	mock "github.com/device-management-toolkit/rpc-go/v2/internal/mocks"
	"github.com/device-management-toolkit/rpc-go/v2/pkg/mkhi"
	"github.com/device-management-toolkit/rpc-go/v2/pkg/pthi"
	"github.com/device-management-toolkit/rpc-go/v2/pkg/upid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

const tepTestVersion = "21.0.0"

var errTEPTest = errors.New("boom")

func tepCaps(features ...upid.TEPFeature) *upid.TEPCapabilities {
	return &upid.TEPCapabilities{MaxVouchers: 3, Features: features}
}

// noVoucher is what CSME returns for a feature without a voucher, as wrapped by tepCall.
func noVoucher() error {
	return fmt.Errorf("TEP command 13: %w", upid.ErrTEPInvalidVoucher)
}

func activeAMTVoucher(t *testing.T) *upid.TEPVoucherState {
	t.Helper()

	var ctx upid.TEPOwnershipContext

	ctx.OwnershipStatus = upid.TEPOwnershipActive
	ctx.OwnershipExpiresOnUTC = 1_824_595_200 // 2027-10-27T00:00:00Z
	copy(ctx.VoucherID[:], "932586c2-d439-4154-86cb-49ba914aa716")
	copy(ctx.OwnerID[:], "9f8968c2-572d-4560-ae77-fabb77b78198")

	dn, err := asn1.Marshal(pkix.Name{CommonName: "Contoso Ownership Service", Organization: []string{"Contoso"}}.ToRDNSequence())
	require.NoError(t, err)
	copy(ctx.CertSubjectDN[:], dn)

	return &upid.TEPVoucherState{Context: ctx}
}

func TestGetTEPInfo(t *testing.T) {
	tests := []struct {
		name     string
		version  string
		explicit bool
		setup    func(t *testing.T, m *mock.MockInterface)
		want     *TEPInfo
	}{
		{
			name:    "CSME before 18 makes no calls and adds no section",
			version: "16.1.25",
		},
		{
			name:     "CSME before 18 with --tep reports not supported",
			version:  "16.1.25",
			explicit: true,
			want:     &TEPInfo{},
		},
		{
			name: "unknown version adds no section",
		},
		{
			name:     "unknown version with --tep reports why",
			explicit: true,
			want:     &TEPInfo{Unavailable: "CSME version could not be read"},
		},
		{
			name:    "firmware capabilities read failure adds no section",
			version: tepTestVersion,
			setup: func(_ *testing.T, m *mock.MockInterface) {
				m.EXPECT().GetFWCapabilities().Return(mkhi.FWCapabilities(0), errTEPTest)
			},
		},
		{
			name:     "firmware capabilities read failure with --tep reports why",
			version:  tepTestVersion,
			explicit: true,
			setup: func(_ *testing.T, m *mock.MockInterface) {
				m.EXPECT().GetFWCapabilities().Return(mkhi.FWCapabilities(0), errTEPTest)
			},
			want: &TEPInfo{Unavailable: "firmware capabilities could not be read"},
		},
		{
			name:    "no TEP capability bit",
			version: tepTestVersion,
			setup: func(_ *testing.T, m *mock.MockInterface) {
				m.EXPECT().GetFWCapabilities().Return(mkhi.FWCapsAMT, nil)
			},
		},
		{
			name:    "supported with no vouchers",
			version: tepTestVersion,
			setup: func(_ *testing.T, m *mock.MockInterface) {
				m.EXPECT().GetFWCapabilities().Return(mkhi.FWCapsAMT|mkhi.FWCapsTEP, nil)
				m.EXPECT().TEPGetCapabilities().Return(tepCaps(upid.TEPFeatureAMT, upid.TEPFeatureOEM1), nil)
				m.EXPECT().TEPGetVoucherStateByFeature(upid.TEPFeatureAMT).Return(nil, noVoucher())
				m.EXPECT().TEPGetVoucherStateByFeature(upid.TEPFeatureOEM1).Return(nil, noVoucher())
				m.EXPECT().GetProvisioningLog().Return(pthi.ProvisioningLog{AcmProvisioningStatus: pthi.PROV_RES_INVALID}, nil)
			},
			want: &TEPInfo{
				Supported:   true,
				MaxVouchers: 3,
				Features:    []string{"AMT", "OEM"},
				Vouchers: []TEPVoucher{
					{Feature: "AMT", Status: tepVoucherNone},
					{Feature: "OEM", Status: tepVoucherNone},
				},
				LastACMAttempt: "No provisioning attempt recorded",
			},
		},
		{
			name:    "active voucher, unreadable voucher and unreadable log",
			version: tepTestVersion,
			setup: func(t *testing.T, m *mock.MockInterface) {
				m.EXPECT().GetFWCapabilities().Return(mkhi.FWCapsTEP, nil)
				m.EXPECT().TEPGetCapabilities().Return(tepCaps(upid.TEPFeatureAMT, upid.TEPFeatureOEM1), nil)
				m.EXPECT().TEPGetVoucherStateByFeature(upid.TEPFeatureAMT).Return(activeAMTVoucher(t), nil)
				m.EXPECT().TEPGetVoucherStateByFeature(upid.TEPFeatureOEM1).Return(nil, errTEPTest)
				m.EXPECT().GetProvisioningLog().Return(pthi.ProvisioningLog{}, errTEPTest)
			},
			want: &TEPInfo{
				Supported:   true,
				MaxVouchers: 3,
				Features:    []string{"AMT", "OEM"},
				Vouchers: []TEPVoucher{
					{
						Feature:          "AMT",
						Status:           "active",
						VoucherID:        "932586c2-d439-4154-86cb-49ba914aa716",
						OwnerID:          "9f8968c2-572d-4560-ae77-fabb77b78198",
						OwnershipExpires: "2027-10-27T00:00:00Z",
						OwnershipService: "CN=Contoso Ownership Service,O=Contoso",
					},
					{Feature: "OEM", Status: statusUnknown},
				},
			},
		},
		{
			name:    "voucher state with ownership not set is no voucher",
			version: tepTestVersion,
			setup: func(_ *testing.T, m *mock.MockInterface) {
				m.EXPECT().GetFWCapabilities().Return(mkhi.FWCapsTEP, nil)
				m.EXPECT().TEPGetCapabilities().Return(tepCaps(upid.TEPFeatureAMT), nil)
				m.EXPECT().TEPGetVoucherStateByFeature(upid.TEPFeatureAMT).Return(&upid.TEPVoucherState{}, nil)
				m.EXPECT().GetProvisioningLog().Return(pthi.ProvisioningLog{AcmProvisioningStatus: pthi.PROV_RES_TEP_OWNERSHIP_EXPIRED}, nil)
			},
			want: &TEPInfo{
				Supported:      true,
				MaxVouchers:    3,
				Features:       []string{"AMT"},
				Vouchers:       []TEPVoucher{{Feature: "AMT", Status: tepVoucherNone}},
				LastACMAttempt: "Expired TEP ownership",
			},
		},
		{
			name:    "TEP capabilities read failure",
			version: tepTestVersion,
			setup: func(_ *testing.T, m *mock.MockInterface) {
				m.EXPECT().GetFWCapabilities().Return(mkhi.FWCapsTEP, nil)
				m.EXPECT().TEPGetCapabilities().Return(nil, errTEPTest)
			},
			want: &TEPInfo{Supported: true, Unavailable: "TEP capabilities could not be read"},
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			m := mock.NewMockInterface(ctrl)

			if tt.setup != nil {
				tt.setup(t, m)
			}

			got := NewInfoService(m, WithHECIAvailable(true)).getTEPInfo(tt.version, tt.explicit)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestGetAMTInfoTEPOnly(t *testing.T) {
	ctrl := gomock.NewController(t)
	m := mock.NewMockInterface(ctrl)

	// --tep alone reads the version for the support check but does not report it.
	m.EXPECT().GetVersionDataFromME("AMT", gomock.Any()).Return(tepTestVersion, nil)
	m.EXPECT().GetFWCapabilities().Return(mkhi.FWCapsTEP, nil)
	m.EXPECT().TEPGetCapabilities().Return(tepCaps(upid.TEPFeatureAMT), nil)
	m.EXPECT().TEPGetVoucherStateByFeature(upid.TEPFeatureAMT).Return(nil, noVoucher())
	m.EXPECT().GetProvisioningLog().Return(pthi.ProvisioningLog{}, nil)

	cmd := &AmtInfoCmd{TEP: true}
	assert.False(t, cmd.HasNoFlagsSet())

	result, err := NewInfoService(m, WithHECIAvailable(true)).GetAMTInfo(cmd)
	require.NoError(t, err)
	require.NotNil(t, result.TEP)
	assert.True(t, result.TEP.Supported)
	assert.Empty(t, result.AMT, "version is read for the check, not reported")
	assert.Nil(t, result.UPID)
}

func TestGetAMTInfoTEPWithoutHECI(t *testing.T) {
	ctrl := gomock.NewController(t)
	m := mock.NewMockInterface(ctrl) // no calls expected

	result, err := NewInfoService(m, WithHECIAvailable(false)).GetAMTInfo(&AmtInfoCmd{TEP: true})
	require.NoError(t, err)
	assert.Nil(t, result.TEP)
}

func TestTEPOutput(t *testing.T) {
	ctrl := gomock.NewController(t)
	m := mock.NewMockInterface(ctrl)
	m.EXPECT().GetFWCapabilities().Return(mkhi.FWCapsTEP, nil)
	m.EXPECT().TEPGetCapabilities().Return(tepCaps(upid.TEPFeatureAMT, upid.TEPFeatureOEM1), nil)
	m.EXPECT().TEPGetVoucherStateByFeature(upid.TEPFeatureAMT).Return(activeAMTVoucher(t), nil)
	m.EXPECT().TEPGetVoucherStateByFeature(upid.TEPFeatureOEM1).Return(nil, noVoucher())
	m.EXPECT().GetProvisioningLog().Return(pthi.ProvisioningLog{AcmProvisioningStatus: pthi.PROV_RES_TEP_HASH_MISMATCH}, nil)

	service := NewInfoService(m, WithHECIAvailable(true))
	result := &InfoResult{TEP: service.getTEPInfo(tepTestVersion, false)}
	cmd := &AmtInfoCmd{TEP: true}

	wantRows := [][2]string{
		{"Supported", "Yes"},
		{"Max Vouchers", "3"},
		{"Features", "AMT, OEM"},
		{"AMT Voucher", "active"},
		{"AMT Voucher ID", "932586c2-d439-4154-86cb-49ba914aa716"},
		{"AMT Owner ID", "9f8968c2-572d-4560-ae77-fabb77b78198"},
		{"AMT Ownership Expires", "2027-10-27T00:00:00Z"},
		{"AMT Ownership Service", "CN=Contoso Ownership Service,O=Contoso"},
		{"OEM Voucher", "none"},
		{"Last ACM Attempt", "TEP owner credential hash mismatch"},
	}

	t.Run("text", func(t *testing.T) {
		text := buildTEPSection(result, cmd, false)
		assert.Contains(t, text, tepSectionTitle)

		for _, row := range wantRows {
			assert.Contains(t, text, row[0])
			assert.Contains(t, text, row[1])
		}

		assert.Empty(t, buildTEPSection(result, &AmtInfoCmd{UPID: true}, false), "hidden when other flags are selected")
		assert.Empty(t, buildTEPSection(&InfoResult{}, cmd, false), "hidden when not read")
	})

	t.Run("table", func(t *testing.T) {
		var buf bytes.Buffer

		require.NoError(t, service.OutputTable(&buf, result, cmd))

		out := buf.String()
		assert.Contains(t, out, tepSectionTitle)
		assert.Contains(t, out, tepFlag)

		for _, row := range wantRows {
			assert.Contains(t, out, row[0])
			assert.Contains(t, out, row[1])
		}
	})

	t.Run("json", func(t *testing.T) {
		var buf bytes.Buffer

		require.NoError(t, service.OutputJSON(&buf, result))

		var got struct {
			TEP *TEPInfo `json:"tep"`
		}

		require.NoError(t, json.Unmarshal(buf.Bytes(), &got))
		assert.Equal(t, result.TEP, got.TEP)
		assert.Contains(t, buf.String(), `"lastAcmAttempt": "TEP owner credential hash mismatch"`)
	})
}

func TestTEPRowsUnavailable(t *testing.T) {
	assert.Equal(t, []infoRow{{label: "Supported", value: "No"}}, tepRows(&TEPInfo{}))
	assert.Equal(t,
		[]infoRow{{label: "Supported", value: "firmware capabilities could not be read", unavailable: true}},
		tepRows(&TEPInfo{Unavailable: "firmware capabilities could not be read"}))
	assert.Equal(t,
		[]infoRow{
			{label: "Supported", value: "Yes"},
			{label: "Vouchers", value: "TEP capabilities could not be read", unavailable: true},
		},
		tepRows(&TEPInfo{Supported: true, Unavailable: "TEP capabilities could not be read"}))

	text := buildTEPSection(&InfoResult{TEP: &TEPInfo{Unavailable: "CSME version could not be read"}}, &AmtInfoCmd{TEP: true}, false)
	assert.Contains(t, text, unavailableValue("CSME version could not be read"))
}
