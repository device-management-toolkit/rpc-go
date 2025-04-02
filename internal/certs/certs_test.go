/*********************************************************************
 * Copyright (c) Intel Corporation 2024
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/

package certs

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func RunNewSignedCompositeTest(t *testing.T, testDer string) {
	rootComp, err := NewRootComposite()
	assert.Nil(t, err)
	assert.NotEmpty(t, rootComp.Pem)
	assert.NotEmpty(t, rootComp.Fingerprint)
	clientComp, err := NewSignedAMTComposite(testDer, &rootComp)
	assert.Nil(t, err)
	assert.NotEmpty(t, clientComp.Pem)
	assert.NotEmpty(t, clientComp.Fingerprint)
	assert.Equal(t, rootComp.Cert.Subject, clientComp.Cert.Issuer)
}

func TestNewSignedCompositeAMT15(t *testing.T) {
	amt15DER := `MIIBCgKCAQEAydspbzaCi8omRjqHKJnuXBJ0BInNlZR22lqy40f/6r4UGpDnAuFt` +
		`yQZ0kWpJp1nfzCk60qgiBKFI2sw5cKTbBDu8n+8GQZ4yvge9//E88salGBBsDpA/` +
		`tkpoQIrlj8MQImZxPRkg0noQz53C3QKvsIgeKsraO5BX2h6iwLiynk0Nqa0ORwMI` +
		`1x3oTNRX5it24uAA2812mJBpcJE8kU4Dgb6bsw4WzTF0drY1WaKHbva18Pwu1VUa` +
		`5H7JDDIbKiS5y+FbkmBQtoiQBQ5jsfoOnecQFnuHGSANjz/ar3IbQo1vSb+uBd3l` +
		`aDrhMwfv8970gsTqUk/xiY+CYdFamjfpSQIDAQAB`

	RunNewSignedCompositeTest(t, amt15DER)
}

func TestNewSignedCompositeAMT16(t *testing.T) {
	amt16DER := `MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAm7XJnC5KCOKdYJVgPg9F` +
		`ROIDIqIG8vRFjsZbyccurpLfTFjnx+9e9ukf5huN6eJmMns0gP4cDe/INvcpGpse` +
		`cGgLT/9KfrRth0qoh35vMMXYsVTlWFZVwigVPYNPTwFXzHMeHodR+yxxyC/MBNvo` +
		`Bo+YVKXYJZFNowlkUxvFfl4gOcNDDXRb2vA33ka2Hk5AVxHm+B0/mgGBIEPVhsMM` +
		`fFvBMeffgshgY8lwf5pvTXTiueEEHQRkWLkIn7cy3H9JyvBMOC37wSkSCpScD+GD` +
		`HNgAOjhRNJjh2v9dzptUN+bY4gLNlIDLyIH+tJMJoX2PPjAqlr7RzDvr+bN2qVVY` +
		`AQIDAQAB`

	RunNewSignedCompositeTest(t, amt16DER)
}

func TestNewCompositeChain(t *testing.T) {
	chain, err := NewCompositeChain("test")
	assert.Nil(t, err)
	assert.NotEmpty(t, chain.Root.Pem)
	assert.NotEmpty(t, chain.Root.Fingerprint)
	assert.NotEmpty(t, chain.Intermediate.Pem)
	assert.NotEmpty(t, chain.Intermediate.Fingerprint)
	assert.NotEmpty(t, chain.Leaf.Pem)
	assert.NotEmpty(t, chain.Leaf.Fingerprint)

	assert.True(t, strings.Contains(chain.Root.Pem, "BEGIN CERTIFICATE"))
	assert.True(t, strings.Contains(chain.Root.Pem, "END CERTIFICATE"))
	strippedPem := chain.Root.StripPem()
	assert.False(t, strings.Contains(strippedPem, "BEGIN CERTIFICATE"))
	assert.False(t, strings.Contains(strippedPem, "END CERTIFICATE"))
}
