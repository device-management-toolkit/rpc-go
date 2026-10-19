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

	ACM bool `help:"Check ACM activation readiness" name:"acm"`
	CCM bool `help:"Check CCM activation readiness" name:"ccm" aliases:"cm"`
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
	if ctx.JsonOutput {
		return renderJSON(w, ctx, result)
	}

	return renderText(w, result)
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
		snapshot = collectInfoSnapshot(cmd, ctx, &commands.AmtInfoCmd{Lan: true, Ras: true})

		result.Checks = append(result.Checks,
			Check{ID: checkIDActivation, Name: checkNameActivation, Status: checkAlreadyActive, Message: "AMT is already activated: " + result.DetectedState},
			Check{ID: checkIDPostHealth, Name: checkNamePostHealth, Status: checkNotEvaluated, Message: "Post-activation checks are not included in this release"},
		)
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
