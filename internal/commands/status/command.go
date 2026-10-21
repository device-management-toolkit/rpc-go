/*********************************************************************
 * Copyright (c) Intel Corporation 2026
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/

package status

import (
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/device-management-toolkit/rpc-go/v2/internal/commands"
	"github.com/device-management-toolkit/rpc-go/v2/pkg/utils"
)

var statusIsElevated = utils.IsElevated

// StatusCmd performs local AMT activation-readiness checks.
type StatusCmd struct {
	commands.AMTBaseCmd

	ACM  bool   `help:"Check ACM activation readiness" name:"acm"`
	CCM  bool   `help:"Check CCM activation readiness" name:"ccm" aliases:"cm"`
	Host string `help:"Console address to probe in direct mode" name:"host"`
}

func (cmd *StatusCmd) Validate() error {
	if cmd.ACM && cmd.CCM {
		return fmt.Errorf("--acm and --ccm cannot be used together")
	}

	return nil
}

func (cmd *StatusCmd) RequiresAMTPassword() bool { return false }

func (cmd *StatusCmd) BeforeApply() error {
	cmd.SkipWSMANSetup = true

	return nil
}

func (cmd *StatusCmd) Run(ctx *commands.Context) error {
	return run(os.Stdout, cmd, ctx)
}

func run(w io.Writer, cmd *StatusCmd, ctx *commands.Context) error {
	if cmd == nil || ctx == nil || ctx.AMTCommand == nil {
		return fmt.Errorf("status requires an AMT command")
	}

	result := cmd.evaluate(ctx)

	var renderErr error
	if ctx.JsonOutput {
		renderErr = renderJSON(w, ctx, result)
	} else {
		renderErr = renderText(w, result)
	}

	if renderErr != nil {
		return renderErr
	}

	return verdictError(result.Verdict)
}

func verdictError(verdict Verdict) error {
	switch verdict.Result {
	case resultNotReady:
		return utils.AmtNotReady
	case resultNotAMT:
		return utils.AmtNotDetected
	case resultUnknown:
		return utils.GenericFailure
	default:
		return nil
	}
}

func (cmd *StatusCmd) evaluate(ctx *commands.Context) report {
	elevated := statusIsElevated()

	meiDriverVersion := ""
	if cmd.HECIAvailable {
		meiDriverVersion = statusGetMEIDriverVersion()
	}

	adapters := utils.GetPlatformAdapters()
	osInfo := utils.GetOSInfo()

	result := report{
		DetectedState:       resultUnknown,
		SelectedCheckSet:    selectedCheckSet(cmd),
		Checks:              initialChecks(elevated, cmd.HECIAvailable, cmd.GetHECIInitError(), meiDriverVersion),
		ProcessorModel:      utils.GetCPUModel(),
		OSDescription:       strings.TrimSpace(strings.TrimSpace(osInfo.Distro) + " " + osInfo.Version),
		WiredAdapterName:    strings.Join(adapters.Wired, ", "),
		WirelessAdapterName: strings.Join(adapters.Wireless, ", "),
	}
	if result.OSDescription == "" {
		result.OSDescription = osInfo.Name
	}

	var snapshot *commands.InfoSnapshot

	if !cmd.HECIAvailable {
		if elevated {
			result.DetectedState = "amt_unavailable"
		} else {
			result.Checks = append(result.Checks, Check{
				ID:      checkIDActivation,
				Name:    checkNameActivation,
				Status:  checkUnavailable,
				Message: "AMT state is unknown; run as administrator/root",
			})
		}
	} else if cmd.ControlMode == commands.ControlModeACM || cmd.ControlMode == commands.ControlModeCCM {
		result.DetectedState = utils.InterpretControlMode(cmd.ControlMode)
		result.SelectedCheckSet = checkSetPost

		var checks []Check

		checks, snapshot = collectPostActivationChecks(cmd, ctx)
		result.Checks = append(result.Checks, checks...)
	} else {
		if cmd.ControlMode == 0 {
			result.DetectedState = "pre_provisioning"
		}

		var checks []Check

		checks, snapshot = collectPreActivationChecks(cmd, ctx)
		result.Checks = append(result.Checks, checks...)
		result.ActivationProfiles = evaluateActivationProfiles(snapshot, result.Checks)
	}

	populateSnapshot(&result, snapshot)

	result.Verdict = EvaluateVerdict(result.Checks)
	result.Host = cmd.Host

	return result
}

func selectedCheckSet(cmd *StatusCmd) string {
	switch {
	case cmd.ACM:
		return checkSetPreACM
	case cmd.CCM:
		return checkSetPreCCM
	default:
		return checkSetPre
	}
}
