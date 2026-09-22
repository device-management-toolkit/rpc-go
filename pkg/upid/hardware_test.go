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
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha512"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"math/big"
	"slices"
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

	t.Logf("TEP features: %v", caps.Features)
	t.Logf("OEM platform ID: %s", hex.EncodeToString(caps.OEMPlatformID[:]))

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

// verifyCSMESignature checks an ECDSA-P384/SHA-384 CSME_SIGNATURE against the
// leaf certificate in its own chain. The encoding of the 512-byte signature
// field is not documented, so DER and raw r||s (big- and little-endian) are
// all tried and the one that verifies is logged.
func verifyCSMESignature(t *testing.T, sig *CSMESignature, signed []byte) {
	t.Helper()

	require.Equal(t, TEPSignatureECDSA384SHA384, sig.SignatureMechanism)

	chain, err := sig.CertificateChain()
	require.NoError(t, err)
	require.NotEmpty(t, chain, "CSME_SIGNATURE has no certificates")

	for i, der := range chain {
		cert, err := x509.ParseCertificate(der)
		require.NoError(t, err, "certificate %d", i)
		t.Logf("  cert[%d]: %s (issuer %s)", i, cert.Subject, cert.Issuer)
	}

	leaf, _ := x509.ParseCertificate(chain[0])
	pub, ok := leaf.PublicKey.(*ecdsa.PublicKey)
	require.True(t, ok, "leaf key is %T, want ECDSA", leaf.PublicKey)

	digest := sha512.Sum384(signed)

	const half = 48 // P-384 scalar size

	raw := sig.Signature[:2*half]
	reversed := func(b []byte) []byte {
		r := slices.Clone(b)
		slices.Reverse(r)

		return r
	}

	encodings := []struct {
		name   string
		verify func() bool
	}{
		{"DER", func() bool { return ecdsa.VerifyASN1(pub, digest[:], trimDER(sig.Signature[:])) }},
		{"raw r||s big-endian", func() bool {
			return ecdsa.Verify(pub, digest[:], new(big.Int).SetBytes(raw[:half]), new(big.Int).SetBytes(raw[half:]))
		}},
		{"raw r||s little-endian", func() bool {
			return ecdsa.Verify(pub, digest[:], new(big.Int).SetBytes(reversed(raw[:half])), new(big.Int).SetBytes(reversed(raw[half:])))
		}},
	}

	for _, e := range encodings {
		if e.verify() {
			t.Logf("CSME signature verified (%s encoding, %d signed bytes)", e.name, len(signed))

			return
		}
	}

	t.Errorf("CSME signature did not verify with any known encoding; signed data %d bytes, signature %s",
		len(signed), hex.EncodeToString(sig.Signature[:2*half+8]))
}

// trimDER returns the DER SEQUENCE at the start of b without trailing padding.
func trimDER(b []byte) []byte {
	const shortFormMax = 0x80

	if len(b) < 2 || b[0] != 0x30 || b[1] >= shortFormMax {
		return b
	}

	return b[:2+int(b[1])]
}
