//go:build amt

/*********************************************************************
 * Copyright (c) Intel Corporation 2026
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/

// Hardware tests: these talk to the real UPID MEI client and are only built
// with the "amt" tag, so CI never runs them. Run from an elevated shell on a
// TEP-capable platform (e.g. Panther Lake, CSME 21):
//
//	go test -tags amt -v -run TestHW ./pkg/upid
//
// They only use read-only commands. TEPGetTimeSyncNonce makes CSME create a
// time-sync nonce (valid 10 minutes); it does not change ownership state.
package upid

import (
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"testing"

	"github.com/device-management-toolkit/rpc-go/v2/pkg/utils"
	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// minTEPMessageLength is the largest TEP request (TEP_SET_TIME_CERTS_CMD).
const minTEPMessageLength = 12020

// hwCommand returns a Command backed by the real HECI driver, with trace
// logging on so raw requests/responses appear in -v output.
func hwCommand(t *testing.T) *Command {
	t.Helper()

	if !utils.IsElevated() {
		t.Fatal("hardware tests need an elevated (Administrator/root) shell")
	}

	level := log.GetLevel()

	log.SetLevel(log.TraceLevel)
	t.Cleanup(func() { log.SetLevel(level) })

	cmd, ok := NewCommand().(*Command)
	require.True(t, ok)

	return cmd
}

// skipOnTEPStatus skips when firmware returned a TEP status (e.g. no voucher
// installed), but fails on transport or parsing errors.
func skipOnTEPStatus(t *testing.T, err error) {
	t.Helper()

	for _, sentinel := range tepStatusErrors {
		if errors.Is(err, sentinel) {
			t.Skipf("firmware returned TEP status: %v", err)
		}
	}

	if errors.Is(err, ErrTEPUnknownStatus) {
		t.Skipf("firmware returned TEP status: %v", err)
	}
}

func randomNonce(t *testing.T) TEPNonce {
	t.Helper()

	var n TEPNonce

	_, err := rand.Read(n[:])
	require.NoError(t, err)

	return n
}

func TestHWMEIClient(t *testing.T) {
	cmd := hwCommand(t)

	require.NoError(t, cmd.initGUID(), "cannot open UPID MEI client - run elevated on a UPID-capable platform")
	defer cmd.Close()

	size := cmd.Heci.GetBufferSize()
	t.Logf("UPID MEI client max message length: %d", size)

	assert.GreaterOrEqual(t, size, uint32(minTEPMessageLength),
		"MEI client cannot carry TEP_SET_TIME_CERTS_CMD (%d bytes)", minTEPMessageLength)
}

func TestHWGetUPID(t *testing.T) {
	upid, err := hwCommand(t).GetUPID()
	if errors.Is(err, ErrUPIDNotProvisioned) {
		t.Skip("UPID not provisioned")
	}

	require.NoError(t, err)
	t.Logf("UPID:\n%s", upid)
}

func TestHWTEPGetCapabilities(t *testing.T) {
	caps, err := hwCommand(t).TEPGetCapabilities()
	require.NoError(t, err)

	t.Logf("TEP max vouchers: %d, features: %v", caps.MaxVouchers, caps.Features)

	assert.True(t, caps.Supports(TEPFeatureAMT), "AMT (101) not listed as a TEP feature")
}

func TestHWTEPGetVoucherIDs(t *testing.T) {
	cmd := hwCommand(t)

	vouchers, err := cmd.TEPGetVouchers()
	require.NoError(t, err, "TEP_GET_VOUCHERS")
	t.Logf("TEP_GET_VOUCHERS: %v", vouchers)

	all, err := cmd.TEPGetAllVoucherIDs()
	require.NoError(t, err, "TEP_GET_ALL_VOUCHERS_ID")
	t.Logf("TEP_GET_ALL_VOUCHERS_ID: %v", all)

	assert.Equal(t, vouchers, all, "commands 5 and 10 disagree")
}

func TestHWTEPGetVoucherStateByFeature(t *testing.T) {
	state, err := hwCommand(t).TEPGetVoucherStateByFeature(TEPFeatureAMT)
	skipOnTEPStatus(t, err)
	require.NoError(t, err)

	logContext(t, &state.Context)
	t.Logf("voucher version: %d", state.VoucherVersion)
}

func TestHWTEPGetOwnershipState(t *testing.T) {
	cmd := hwCommand(t)

	ids, err := cmd.TEPGetAllVoucherIDs()
	require.NoError(t, err)

	if len(ids) == 0 {
		t.Skip("no TEP vouchers installed")
	}

	for _, id := range ids {
		t.Run(id.String(), func(t *testing.T) {
			state, err := cmd.TEPGetOwnershipState(randomNonce(t), id)
			skipOnTEPStatus(t, err)
			require.NoError(t, err)

			logContext(t, &state.Context)
			assert.Equal(t, id, state.Context.VoucherID)

			// A valid signature confirms the response layout (context padding).
			verifyCSMESignature(t, &state.Signature, state.SignedData)
		})
	}
}

func TestHWTEPGetTimeSyncNonce(t *testing.T) {
	cmd := hwCommand(t)

	first, err := cmd.TEPGetTimeSyncNonce(randomNonce(t))
	require.NoError(t, err)

	t.Logf("CSME nonce: %s", hex.EncodeToString(first.CSMENonce[:]))
	t.Logf("CSME timestamp: %d (0 = TEP time not set)", first.Signature.Timestamp)
	assert.NotEqual(t, TEPNonce{}, first.CSMENonce)

	verifyCSMESignature(t, &first.Signature, first.SignedData)

	// CSME returns the same nonce while it is valid (10 minutes).
	second, err := cmd.TEPGetTimeSyncNonce(randomNonce(t))
	require.NoError(t, err)
	assert.Equal(t, first.CSMENonce, second.CSMENonce, "nonce changed between back-to-back calls")
}

func logContext(t *testing.T, c *TEPOwnershipContext) {
	t.Helper()

	t.Logf("voucher %s: status=%s assertion=%s owner=%s", c.VoucherID, c.OwnershipStatus, c.Assertion, c.OwnerID)
	t.Logf("  credential: %s %s %s", c.CredentialType, c.HashAlgorithm,
		hex.EncodeToString(c.OwnerCredentialHash[:max(c.HashAlgorithm.Size(), 0)]))
	t.Logf("  created=%d expires=%d ownershipExpires=%d active=%d",
		c.CreatedOnUTC, c.ExpiresOnUTC, c.OwnershipExpiresOnUTC, c.OwnershipActiveTimestamp)
	t.Logf("  features=%v OEM_ID=0x%04x prev=%s", c.Features, c.OEMID, c.PrevVoucherID)
}

// verifyCSMESignature logs the CSME certificate chain and verifies the
// signature against its leaf. A valid signature also confirms that the
// response was parsed at the right offsets.
func verifyCSMESignature(t *testing.T, sig *CSMESignature, signed []byte) {
	t.Helper()

	chain, err := sig.CertificateChain()
	require.NoError(t, err)

	for i, der := range chain {
		cert, err := x509.ParseCertificate(der)
		require.NoError(t, err, "certificate %d", i)
		t.Logf("  cert[%d]: %s (issuer %s)", i, cert.Subject, cert.Issuer)
	}

	require.NoError(t, sig.Verify(signed), "mechanism=%d timestamp=%d signed=%d bytes",
		sig.SignatureMechanism, sig.Timestamp, len(signed))
	t.Logf("CSME signature verified (%d signed bytes)", len(signed))
}
