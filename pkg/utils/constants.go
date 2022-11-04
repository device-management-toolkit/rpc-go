/*********************************************************************
 * Copyright (c) Intel Corporation 2021
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/

// Package utils ...
package utils

const (
	// ProjectName is the name of the executable
	ProjectName = "rpc"
	// ProjectVersion is the full version of this executable
	ProjectVersion = "2.3.0"
	// ProtocolVersion is the version used between RPC and RPS
	ProtocolVersion = "4.0.0"
	// ClientName is the name of the exectable
	ClientName = "RPC"
	// LMSAddress is used for determing what address to connect to LMS on
	LMSAddress = "localhost"
	// LMSPort is used for determining what port to connect to LMS on
	LMSPort = "16992"
	// MPSServerMaxLength is the max length of the servername
	MPSServerMaxLength = 256
	// Success Return Code
	Success = 0
	// ErrGeneralFailure Return Code
	ErrGeneralFailure = -1
	// ErrAccess Return Code
	ErrAccess = -1
)
