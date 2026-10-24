/*********************************************************************
 * Copyright (c) Intel Corporation 2026
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/

package status

import (
	"encoding/json"
	"io"
	"strings"
	"time"

	"github.com/device-management-toolkit/rpc-go/v2/internal/commands"
	"github.com/device-management-toolkit/rpc-go/v2/pkg/utils"
	"github.com/device-management-toolkit/rpc-go/v2/pkg/version"
)

func renderJSON(w io.Writer, ctx *commands.Context, result report) error {
	versionInfo := version.Get()
	output := jsonOutput{
		Metadata: jsonMetadata{
			Command:          "status",
			Timestamp:        time.Now().Format(time.RFC3339),
			RPCVersion:       versionInfo.Version,
			Elevated:         utils.IsElevated(),
			PasswordProvided: ctx != nil && strings.TrimSpace(ctx.AMTPassword) != "",
		},
		Evaluation: evaluationFor(result),
		Checks:     result.Checks,
	}

	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")

	return encoder.Encode(output)
}

func evaluationFor(result report) evaluation {
	eval := evaluation{
		DetectedState:         result.DetectedState,
		SelectedCheckSet:      result.SelectedCheckSet,
		DeviceType:            result.DeviceType,
		AMTVersion:            result.AMTVersion,
		AMTDNSSuffix:          result.AMTDNSSuffix,
		OSDNSSuffix:           result.OSDNSSuffix,
		AMTOperationalState:   result.AMTOperationalState,
		RemoteAccess:          result.RemoteAccess,
		TLSMode:               result.TLSMode,
		Host:                  result.Host,
		ProcessorModel:        result.ProcessorModel,
		OSDescription:         result.OSDescription,
		WiredAdapterName:      result.WiredAdapterName,
		WirelessAdapterName:   result.WirelessAdapterName,
		WiredAdapterStatus:    result.WiredAdapterStatus,
		WirelessAdapterStatus: result.WirelessAdapterStatus,
		ActivationProfiles:    result.ActivationProfiles,
		OverallResult:         result.Verdict.Result,
		OverallStatus:         result.Verdict.Status,
		TotalChecks:           len(result.Checks),
		ReadyToProvision:      result.Verdict.ReadyToProvision,
		ReadyForManagement:    result.Verdict.ReadyForManagement,
	}

	for _, check := range result.Checks {
		switch check.Status {
		case checkPass:
			eval.Passed++
		case checkWarn:
			eval.Warned++
		case checkFail:
			eval.Failed++
		case checkUnavailable, checkNotEvaluated, checkAlreadyActive:
			eval.NotVerified++
		}
	}

	return eval
}
