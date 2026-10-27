/*********************************************************************
 * Copyright (c) Intel Corporation 2026
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/

package amt

import (
	"errors"
	"testing"

	"github.com/device-management-toolkit/rpc-go/v2/pkg/upid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeUPID records TEP calls and returns canned values.
type fakeUPID struct {
	calls     []string
	feature   upid.TEPFeature
	reqID     upid.TEPNonce
	voucherID upid.TEPVoucherID
	chain     [][]byte
	ocsp      [][]byte
	cms       []byte
	err       error
}

func (f *fakeUPID) GetUPID() (*upid.UPID, error) { return nil, f.err }

func (f *fakeUPID) GetFullCertificateChain(_ upid.CertIndex) ([][]byte, error) {
	f.calls = append(f.calls, "chain")

	return [][]byte{{0x30}}, f.err
}

func (f *fakeUPID) TEPGetCapabilities() (*upid.TEPCapabilities, error) {
	f.calls = append(f.calls, "caps")

	return &upid.TEPCapabilities{MaxVouchers: 3}, f.err
}

func (f *fakeUPID) TEPGetVouchers() ([]upid.TEPVoucherID, error) {
	f.calls = append(f.calls, "vouchers")

	return []upid.TEPVoucherID{{'a'}}, f.err
}

func (f *fakeUPID) TEPGetAllVoucherIDs() ([]upid.TEPVoucherID, error) {
	f.calls = append(f.calls, "all")

	return []upid.TEPVoucherID{{'b'}}, f.err
}

func (f *fakeUPID) TEPGetVoucherStateByFeature(feature upid.TEPFeature) (*upid.TEPVoucherState, error) {
	f.calls = append(f.calls, "state")
	f.feature = feature

	return &upid.TEPVoucherState{Version: upid.TEPVoucherVersion1, HasVersion: true}, f.err
}

func (f *fakeUPID) TEPGetOwnershipState(reqID upid.TEPNonce, voucherID upid.TEPVoucherID) (*upid.TEPOwnershipState, error) {
	f.calls = append(f.calls, "ownership")
	f.reqID = reqID
	f.voucherID = voucherID

	return &upid.TEPOwnershipState{}, f.err
}

func (f *fakeUPID) TEPGetTimeSyncNonce(reqID upid.TEPNonce) (*upid.TEPTimeSyncNonce, error) {
	f.calls = append(f.calls, "nonce")
	f.reqID = reqID

	return &upid.TEPTimeSyncNonce{CSMENonce: upid.TEPNonce{9}}, f.err
}

func (f *fakeUPID) TEPSetTimeAndCerts(certChain, ocspResponses [][]byte) error {
	f.calls = append(f.calls, "settime")
	f.chain, f.ocsp = certChain, ocspResponses

	return f.err
}

func (f *fakeUPID) TEPRequestOwnershipVoucher(request *upid.TEPBinaryVoucherRequest) ([]byte, error) {
	f.calls = append(f.calls, "request")
	f.voucherID = request.VoucherID

	return []byte{0x30}, f.err
}

func (f *fakeUPID) TEPSetOwnershipVoucher(voucherID upid.TEPVoucherID, voucherCMS []byte) error {
	f.calls = append(f.calls, "set")
	f.voucherID, f.cms = voucherID, voucherCMS

	return f.err
}

func (f *fakeUPID) TEPRemoveOwnershipVoucher(voucherID upid.TEPVoucherID) error {
	f.calls = append(f.calls, "remove")
	f.voucherID = voucherID

	return f.err
}

func TestAMTCommandTEPDelegation(t *testing.T) {
	f := &fakeUPID{}
	cmd := AMTCommand{UPID: f}

	reqID := upid.TEPNonce{1, 2, 3}
	voucherID := upid.TEPVoucherID{'v'}

	caps, err := cmd.TEPGetCapabilities()
	require.NoError(t, err)
	assert.Equal(t, 3, caps.MaxVouchers)

	vouchers, err := cmd.TEPGetVouchers()
	require.NoError(t, err)
	assert.Equal(t, []upid.TEPVoucherID{{'a'}}, vouchers)

	all, err := cmd.TEPGetAllVoucherIDs()
	require.NoError(t, err)
	assert.Equal(t, []upid.TEPVoucherID{{'b'}}, all)

	state, err := cmd.TEPGetVoucherStateByFeature(upid.TEPFeatureAMT)
	require.NoError(t, err)
	assert.Equal(t, upid.TEPVoucherVersion1, state.Version)
	assert.Equal(t, upid.TEPFeatureAMT, f.feature)

	_, err = cmd.TEPGetOwnershipState(reqID, voucherID)
	require.NoError(t, err)
	assert.Equal(t, voucherID, f.voucherID)
	assert.Equal(t, reqID, f.reqID)

	nonce, err := cmd.TEPGetTimeSyncNonce(reqID)
	require.NoError(t, err)
	assert.Equal(t, upid.TEPNonce{9}, nonce.CSMENonce)

	chain, ocsp := [][]byte{{1}}, [][]byte{{2}}
	require.NoError(t, cmd.TEPSetTimeAndCerts(chain, ocsp))
	assert.Equal(t, chain, f.chain)
	assert.Equal(t, ocsp, f.ocsp)

	cms, err := cmd.TEPRequestOwnershipVoucher(&upid.TEPBinaryVoucherRequest{VoucherID: voucherID})
	require.NoError(t, err)
	assert.Equal(t, []byte{0x30}, cms)

	require.NoError(t, cmd.TEPSetOwnershipVoucher(voucherID, []byte{0x31}))
	assert.Equal(t, []byte{0x31}, f.cms)

	require.NoError(t, cmd.TEPRemoveOwnershipVoucher(voucherID))
	assert.Equal(t, voucherID, f.voucherID)

	fullChain, err := cmd.GetUPIDFullCertificateChain(upid.CertIndexTEP)
	require.NoError(t, err)
	assert.Equal(t, [][]byte{{0x30}}, fullChain)

	assert.Equal(t, []string{
		"caps", "vouchers", "all", "state", "ownership", "nonce",
		"settime", "request", "set", "remove", "chain",
	}, f.calls)
}

func TestAMTCommandTEPPropagatesErrors(t *testing.T) {
	cmd := AMTCommand{UPID: &fakeUPID{err: upid.ErrTEPTimeNotSet}}

	_, err := cmd.TEPGetTimeSyncNonce(upid.TEPNonce{})
	require.ErrorIs(t, err, upid.ErrTEPTimeNotSet)

	_, err = cmd.TEPGetCapabilities()
	require.True(t, errors.Is(err, upid.ErrTEPTimeNotSet))
}
