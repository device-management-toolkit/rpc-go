/*********************************************************************
 * Copyright (c) Intel Corporation 2026
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/

package commands

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"slices"
	"strings"

	"github.com/device-management-toolkit/go-wsman-messages/v2/pkg/wsman/cim/models"
	"github.com/device-management-toolkit/go-wsman-messages/v2/pkg/wsman/cim/power"
	"github.com/device-management-toolkit/rpc-go/v2/pkg/utils"
	log "github.com/sirupsen/logrus"
)

// powerActions maps the friendly action names accepted by `power action --state`
// to the CIM_PowerManagementService.RequestPowerStateChange power state values.
var powerActions = map[string]power.PowerState{
	"off":            power.PowerOffHard,
	"soft-off":       power.PowerOffSoftGraceful,
	"reset":          power.MasterBusReset,
	"graceful-reset": power.MasterBusResetGraceful,
	"cycle":          power.PowerCycleOffHard,
	"sleep":          power.SleepDeep,
	"hibernate":      power.Hibernate,
	"nmi":            power.DiagnosticInterruptNMI,
}

// PowerCmd groups the power state subcommands.
type PowerCmd struct {
	State  PowerStateCmd  `cmd:"" name:"state" help:"Show the current power state and the power actions AMT will accept"`
	Action PowerActionCmd `cmd:"" name:"action" help:"Request a power state change of the local device"`
}

// PowerStateEntry is a CIM power state value with its DMTF name and, when it can be
// requested with `power action`, the matching action name.
type PowerStateEntry struct {
	Value  int    `json:"value"`
	Name   string `json:"name"`
	Action string `json:"action,omitempty"`
}

// PowerStateResult is the output of `power state`.
type PowerStateResult struct {
	PowerState                    PowerStateEntry   `json:"powerState"`
	RequestedPowerState           PowerStateEntry   `json:"requestedPowerState"`
	AvailableRequestedPowerStates []PowerStateEntry `json:"availableRequestedPowerStates"`
	AvailableActions              []string          `json:"availableActions"`
}

// PowerActionResult is the output of `power action`.
type PowerActionResult struct {
	Action      string `json:"action"`
	PowerState  int    `json:"powerState"`
	ReturnValue int    `json:"returnValue"`
	Status      string `json:"status"`
}

// PowerStateCmd reports the current power state.
type PowerStateCmd struct {
	AMTBaseCmd
}

// Run executes the power state command.
func (cmd *PowerStateCmd) Run(ctx *Context) error {
	if err := ensurePowerRuntime(ctx, &cmd.AMTBaseCmd); err != nil {
		return err
	}

	result, err := getPowerState(&cmd.AMTBaseCmd)
	if err != nil {
		return err
	}

	return writePowerOutput(os.Stdout, ctx.JsonOutput, result, func(w io.Writer) {
		fmt.Fprint(w, renderInfoHeader("POWER STATE"))
		fmt.Fprint(w, renderInfoRow("Power State", result.PowerState.Name))
		fmt.Fprint(w, renderInfoRow("Requested State", result.RequestedPowerState.Name))
		fmt.Fprint(w, renderInfoRow("Available Actions", strings.Join(result.AvailableActions, ", ")))
		fmt.Fprintln(w)
	})
}

// PowerActionCmd requests a power state change.
type PowerActionCmd struct {
	AMTBaseCmd
	State string `help:"Power action to perform" name:"state" required:"" enum:"off,soft-off,reset,graceful-reset,cycle,sleep,hibernate,nmi"`
}

// Run executes the power action command.
func (cmd *PowerActionCmd) Run(ctx *Context) error {
	if err := ensurePowerRuntime(ctx, &cmd.AMTBaseCmd); err != nil {
		return err
	}

	requested, ok := powerActions[cmd.State]
	if !ok {
		return utils.CustomError{Code: utils.InvalidUserInput.Code, Message: utils.InvalidUserInput.Message, Details: "unsupported power action: " + cmd.State}
	}

	current, err := getPowerState(&cmd.AMTBaseCmd)
	if err != nil {
		return err
	}

	// Some firmware leaves AvailableRequestedPowerStates empty; only enforce it when reported.
	if len(current.AvailableRequestedPowerStates) > 0 && !slices.Contains(current.AvailableActions, cmd.State) {
		return utils.CustomError{
			Code:    utils.InvalidUserInput.Code,
			Message: utils.InvalidUserInput.Message,
			Details: fmt.Sprintf("power action %q is not available in the current power state (%s); available: %s", cmd.State, current.PowerState.Name, strings.Join(current.AvailableActions, ", ")),
		}
	}

	log.Infof("requesting power action %s", cmd.State)

	response, err := cmd.WSMan.RequestPowerStateChange(requested)
	if err != nil {
		return utils.CustomError{Code: utils.WSMANMessageError.Code, Message: utils.WSMANMessageError.Message, Details: err.Error()}
	}

	returnValue := response.Body.RequestPowerStateChangeResponse.ReturnValue
	if returnValue != power.ReturnValueCompletedWithNoError {
		return utils.CustomError{
			Code:    utils.WSMANMessageError.Code,
			Message: utils.WSMANMessageError.Message,
			Details: fmt.Sprintf("RequestPowerStateChange returned %s (%d)", returnValue.String(), int(returnValue)),
		}
	}

	result := PowerActionResult{
		Action:      cmd.State,
		PowerState:  int(requested),
		ReturnValue: int(returnValue),
		Status:      "success",
	}

	return writePowerOutput(os.Stdout, ctx.JsonOutput, result, func(w io.Writer) {
		fmt.Fprint(w, renderInfoHeader("POWER ACTION"))
		fmt.Fprint(w, renderInfoRow("Action", result.Action))
		fmt.Fprint(w, renderInfoRow("Status", result.Status))
		fmt.Fprintln(w)
	})
}

// ensurePowerRuntime checks the device is activated and sets up the WSMAN client.
func ensurePowerRuntime(ctx *Context, base *AMTBaseCmd) error {
	if base.ControlMode == 0 {
		log.Error(utils.DeviceNotActivated)

		return utils.DeviceNotActivated
	}

	if err := base.EnsureAMTPassword(ctx, base); err != nil {
		return err
	}

	return base.EnsureWSMAN(ctx)
}

func getPowerState(base *AMTBaseCmd) (PowerStateResult, error) {
	items, err := base.WSMan.GetPowerState()
	if err != nil {
		return PowerStateResult{}, utils.CustomError{Code: utils.WSMANMessageError.Code, Message: utils.WSMANMessageError.Message, Details: err.Error()}
	}

	if len(items) == 0 {
		return PowerStateResult{}, utils.CustomError{Code: utils.WSMANMessageError.Code, Message: utils.WSMANMessageError.Message, Details: "no CIM_AssociatedPowerManagementService instance returned"}
	}

	return newPowerStateResult(items[0].PowerState, items[0].RequestedPowerState, items[0].AvailableRequestedPowerStates), nil
}

func newPowerStateResult(state models.PowerState, requested models.RequestedPowerState, available []models.AvailableRequestedPowerStates) PowerStateResult {
	result := PowerStateResult{
		PowerState:                    powerStateEntry(int(state)),
		RequestedPowerState:           powerStateEntry(int(requested)),
		AvailableRequestedPowerStates: []PowerStateEntry{},
		AvailableActions:              []string{},
	}

	for _, value := range available {
		entry := powerStateEntry(int(value))

		for name, action := range powerActions {
			if int(action) == int(value) {
				entry.Action = name
				result.AvailableActions = append(result.AvailableActions, name)
			}
		}

		result.AvailableRequestedPowerStates = append(result.AvailableRequestedPowerStates, entry)
	}

	slices.Sort(result.AvailableActions)

	return result
}

// powerStateEntry names a raw CIM power state value using the DMTF PowerState names.
// Note AMT's behavior for some values differs from the DMTF name (e.g. 8 is a hard
// power off on AMT), which is why available states also carry the action name.
func powerStateEntry(value int) PowerStateEntry {
	return PowerStateEntry{Value: value, Name: models.PowerState(value).String()}
}

func writePowerOutput(w io.Writer, jsonOutput bool, result any, text func(io.Writer)) error {
	if !jsonOutput {
		text(w)

		return nil
	}

	outBytes, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return err
	}

	_, err = fmt.Fprintln(w, string(outBytes))

	return err
}
