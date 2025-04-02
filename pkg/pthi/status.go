/*********************************************************************
 * Copyright (c) Intel Corporation 2024
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/

package pthi

type Status uint32

const (
	AMT_STATUS_SUCCESS                    Status = 0
	AMT_STATUS_INTERNAL_ERROR             Status = 1
	AMT_STATUS_NOT_READY                  Status = 2
	AMT_STATUS_INVALID_AMT_MODE           Status = 3
	AMT_STATUS_INVALID_MESSAGE_LENGTH     Status = 4
	AMT_STATUS_NOT_PERMITTED              Status = 16
	AMT_STATUS_MAX_LIMIT_REACHED          Status = 23
	AMT_STATUS_INVALID_PARAMETER          Status = 36
	AMT_STATUS_RNG_GENERATION_IN_PROGRESS Status = 47
	AMT_STATUS_RNG_NOT_READY              Status = 48
	AMT_STATUS_CERTIFICATE_NOT_READY      Status = 49
	AMT_STATUS_INVALID_HANDLE             Status = 2053
	AMT_STATUS_NOT_FOUND                  Status = 2068
)

func (s Status) String() string {
	switch s {
	case AMT_STATUS_SUCCESS:
		return "AMT_STATUS_SUCCESS"
	case AMT_STATUS_INTERNAL_ERROR:
		return "AMT_STATUS_INTERNAL_ERROR"
	case AMT_STATUS_NOT_READY:
		return "AMT_STATUS_NOT_READY"
	case AMT_STATUS_INVALID_AMT_MODE:
		return "AMT_STATUS_INVALID_AMT_MODE"
	case AMT_STATUS_INVALID_MESSAGE_LENGTH:
		return "AMT_STATUS_INVALID_MESSAGE_LENGTH"
	case AMT_STATUS_NOT_PERMITTED:
		return "AMT_STATUS_NOT_PERMITTED"
	case AMT_STATUS_MAX_LIMIT_REACHED:
		return "AMT_STATUS_MAX_LIMIT_REACHED"
	case AMT_STATUS_INVALID_PARAMETER:
		return "AMT_STATUS_INVALID_PARAMETER"
	case AMT_STATUS_RNG_GENERATION_IN_PROGRESS:
		return "AMT_STATUS_RNG_GENERATION_IN_PROGRESS"
	case AMT_STATUS_RNG_NOT_READY:
		return "AMT_STATUS_RNG_NOT_READY"
	case AMT_STATUS_CERTIFICATE_NOT_READY:
		return "AMT_STATUS_CERTIFICATE_NOT_READY"
	case AMT_STATUS_INVALID_HANDLE:
		return "AMT_STATUS_INVALID_HANDLE"
	case AMT_STATUS_NOT_FOUND:
		return "AMT_STATUS_NOT_FOUND"
	}

	return "AMT_STATUS_UNKNOWN"
}
