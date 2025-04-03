/*********************************************************************
 * Copyright (c) Intel Corporation 2021
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/
package utils

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestLookupEnvOrString_Default(t *testing.T) {
	result := LookupEnv("URL")
	assert.Equal(t, "", result)
}
func TestInterpretControlMode0(t *testing.T) {
	algorithm := InterpretControlMode(0)
	assert.Equal(t, "pre-provisioning state", algorithm)
}
func TestInterpretControlMode1(t *testing.T) {
	algorithm := InterpretControlMode(1)
	assert.Equal(t, "activated in client control mode", algorithm)
}

func TestInterpretControlMode2(t *testing.T) {
	algorithm := InterpretControlMode(2)
	assert.Equal(t, "activated in admin control mode", algorithm)
}

func TestInterpretControlMode3(t *testing.T) {
	algorithm := InterpretControlMode(3)
	assert.Equal(t, "unknown state", algorithm)
}

func TestInterpretHashAlgorithm0(t *testing.T) {
	hashSize, algorithm := InterpretHashAlgorithm(0)
	assert.Equal(t, "MD5", algorithm)
	assert.Equal(t, 16, hashSize)
}
func TestInterpretHashAlgorithm1(t *testing.T) {
	hashSize, algorithm := InterpretHashAlgorithm(1)
	assert.Equal(t, "SHA1", algorithm)
	assert.Equal(t, 20, hashSize)
}
func TestInterpretHashAlgorithm2(t *testing.T) {
	hashSize, algorithm := InterpretHashAlgorithm(2)
	assert.Equal(t, "SHA256", algorithm)
	assert.Equal(t, 32, hashSize)
}
func TestInterpretHashAlgorithm3(t *testing.T) {
	hashSize, algorithm := InterpretHashAlgorithm(3)
	assert.Equal(t, "SHA512", algorithm)
	assert.Equal(t, 64, hashSize)
}
func TestInterpretHashAlgorithm4(t *testing.T) {
	hashSize, algorithm := InterpretHashAlgorithm(4)
	assert.Equal(t, "UNKNOWN", algorithm)
	assert.Equal(t, 0, hashSize)
}

func TestInterpretRemoteAccessTrigger0(t *testing.T) {
	result := InterpretRemoteAccessTrigger(0)
	assert.Equal(t, "user initiated", result)
}
func TestInterpretRemoteAccessTrigger1(t *testing.T) {
	result := InterpretRemoteAccessTrigger(1)
	assert.Equal(t, "alert", result)
}
func TestInterpretRemoteAccessTrigger2(t *testing.T) {
	result := InterpretRemoteAccessTrigger(2)
	assert.Equal(t, "periodic", result)
}
func TestInterpretRemoteAccessTrigger3(t *testing.T) {
	result := InterpretRemoteAccessTrigger(3)
	assert.Equal(t, "provisioning", result)
}
func TestInterpretRemoteAccessTrigger4(t *testing.T) {
	result := InterpretRemoteAccessTrigger(4)
	assert.Equal(t, "unknown", result)
}

func TestInterpretAMTNetworkConnectionStatus0(t *testing.T) {
	result := InterpretAMTNetworkConnectionStatus(0)
	assert.Equal(t, "direct", result)
}
func TestInterpretAMTNetworkConnectionStatus1(t *testing.T) {
	result := InterpretAMTNetworkConnectionStatus(1)
	assert.Equal(t, "vpn", result)
}
func TestInterpretAMTNetworkConnectionStatus2(t *testing.T) {
	result := InterpretAMTNetworkConnectionStatus(2)
	assert.Equal(t, "outside enterprise", result)
}
func TestInterpretAMTNetworkConnectionStatus3(t *testing.T) {
	result := InterpretAMTNetworkConnectionStatus(3)
	assert.Equal(t, "unknown", result)
}

func TestInterpretRemoteAccessConnectionStatus0(t *testing.T) {
	result := InterpretRemoteAccessConnectionStatus(0)
	assert.Equal(t, "not connected", result)
}
func TestInterpretRemoteAccessConnectionStatus1(t *testing.T) {
	result := InterpretRemoteAccessConnectionStatus(1)
	assert.Equal(t, "connecting", result)
}
func TestInterpretRemoteAccessConnectionStatus2(t *testing.T) {
	result := InterpretRemoteAccessConnectionStatus(2)
	assert.Equal(t, "connected", result)
}
func TestInterpretRemoteAccessConnectionStatus3(t *testing.T) {
	result := InterpretRemoteAccessConnectionStatus(3)
	assert.Equal(t, "unknown", result)
}
