/*********************************************************************
 * Copyright (c) Intel Corporation 2021
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/
package utils

import "os"

const unknown = "unknown"

func InterpretControlMode(mode int) string {
	switch mode {
	case 0:
		return "pre-provisioning state"
	case 1:
		return "activated in client control mode"
	case 2:
		return "activated in admin control mode"
	default:
		return unknown + " state"
	}
}

func LookupEnv(key string) string {
	if val, ok := os.LookupEnv(key); ok {
		return val
	}

	return ""
}

func InterpretHashAlgorithm(hashAlgorithm int) (hashSize int, algorithm string) {
	switch hashAlgorithm {
	case 0: // MD5
		hashSize = 16
		algorithm = "MD5"
	case 1: // SHA1
		hashSize = 20
		algorithm = "SHA1"
	case 2: // SHA256
		hashSize = 32
		algorithm = "SHA256"
	case 3: // SHA512
		hashSize = 64
		algorithm = "SHA512"
	default:
		hashSize = 0
		algorithm = "UNKNOWN"
	}

	return
}

func InterpretAMTNetworkConnectionStatus(status int) string {
	switch status {
	case 0:
		return "direct"
	case 1:
		return "vpn"
	case 2:
		return "outside enterprise"
	default:
		return unknown
	}
}
func InterpretRemoteAccessConnectionStatus(status int) string {
	switch status {
	case 0:
		return "not connected"
	case 1:
		return "connecting"
	case 2:
		return "connected"
	default:
		return unknown
	}
}
func InterpretRemoteAccessTrigger(status int) string {
	switch status {
	case 0:
		return "user initiated"
	case 1:
		return "alert"
	case 2:
		return "periodic"
	case 3:
		return "provisioning"
	default:
		return unknown
	}
}
