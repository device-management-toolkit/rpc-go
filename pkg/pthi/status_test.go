/*********************************************************************
 * Copyright (c) Intel Corporation 2024
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/

package pthi

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestAmtStatus_String(t *testing.T) {
	tests := []struct {
		s    Status
		want string
	}{
		{
			s:    AMT_STATUS_SUCCESS,
			want: "AMT_STATUS_SUCCESS",
		},
		{
			s:    AMT_STATUS_INTERNAL_ERROR,
			want: "AMT_STATUS_INTERNAL_ERROR",
		},
		{
			s:    AMT_STATUS_NOT_READY,
			want: "AMT_STATUS_NOT_READY",
		},
		{
			s:    AMT_STATUS_INVALID_AMT_MODE,
			want: "AMT_STATUS_INVALID_AMT_MODE",
		},
		{
			s:    AMT_STATUS_INVALID_MESSAGE_LENGTH,
			want: "AMT_STATUS_INVALID_MESSAGE_LENGTH",
		},
		{
			s:    AMT_STATUS_NOT_PERMITTED,
			want: "AMT_STATUS_NOT_PERMITTED",
		},
		{
			s:    AMT_STATUS_MAX_LIMIT_REACHED,
			want: "AMT_STATUS_MAX_LIMIT_REACHED",
		},
		{
			s:    AMT_STATUS_INVALID_PARAMETER,
			want: "AMT_STATUS_INVALID_PARAMETER",
		},
		{
			s:    AMT_STATUS_RNG_GENERATION_IN_PROGRESS,
			want: "AMT_STATUS_RNG_GENERATION_IN_PROGRESS",
		},
		{
			s:    AMT_STATUS_RNG_NOT_READY,
			want: "AMT_STATUS_RNG_NOT_READY",
		},
		{
			s:    AMT_STATUS_CERTIFICATE_NOT_READY,
			want: "AMT_STATUS_CERTIFICATE_NOT_READY",
		},
		{
			s:    AMT_STATUS_INVALID_HANDLE,
			want: "AMT_STATUS_INVALID_HANDLE",
		},
		{
			s:    AMT_STATUS_NOT_FOUND,
			want: "AMT_STATUS_NOT_FOUND",
		},
		{
			s:    100,
			want: "AMT_STATUS_UNKNOWN",
		},
	}
	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			assert.Equalf(t, tt.want, tt.s.String(), "String()")
		})
	}
}
