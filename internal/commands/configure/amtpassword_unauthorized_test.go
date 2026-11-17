/*********************************************************************
 * Copyright (c) Intel Corporation 2026
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/

package configure

import (
	"errors"
	"fmt"
	"testing"

	"github.com/device-management-toolkit/rpc-go/v2/pkg/utils"
	"github.com/stretchr/testify/require"
)

// wsmanPostErr builds the error go-wsman-messages returns for an HTTP status
// >= 401, the way the library builds it (pkg/wsman/client/wsman.go).
func wsmanPostErr(status, body string) error {
	errPostResponse := errors.New("wsman.Client post received")

	return fmt.Errorf("%w: %v\n%v", errPostResponse, status, body)
}

func TestAMTPassError(t *testing.T) {
	tests := []struct {
		name             string
		err              error
		wantText         string
		wantUnauthorized bool
	}{
		{"HTTP 401", wsmanPostErr("401 Unauthorized", "<html>Unauthorized</html>"), "Received 401 unauthorized", true},
		{"HTTP 401 wrapped", fmt.Errorf("get: %w", wsmanPostErr("401 Unauthorized", "")), "Received 401 unauthorized", true},
		{"HTTP 500 whose body contains 401", wsmanPostErr("500 Internal Server Error", "<html>error 401</html>"), "Received 401 unauthorized", false},
		{"other text with 401", errors.New("code 401 somewhere"), "Received 401 unauthorized", false},
		{"other error", errors.New("connection reset"), "connection reset", false},
		{"coded error", utils.WSMANMessageError, utils.WSMANMessageError.Error(), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := amtPassError(tt.err)

			// The CLI's message is unchanged, and no exit code leaks through.
			require.Equal(t, tt.wantText, got.Error())
			require.False(t, errors.As(got, &utils.CustomError{}))
			require.Equal(t, tt.wantUnauthorized, errors.Is(got, ErrAMTUnauthorized))
		})
	}

	require.NoError(t, amtPassError(nil))
}

func TestAMTPassError_KeepsTheStepMessage(t *testing.T) {
	err := fmt.Errorf("failed to get AMT general settings: %w", amtPassError(wsmanPostErr("401 Unauthorized", "")))

	require.Equal(t, "failed to get AMT general settings: Received 401 unauthorized", err.Error())
	require.ErrorIs(t, err, ErrAMTUnauthorized)
}
