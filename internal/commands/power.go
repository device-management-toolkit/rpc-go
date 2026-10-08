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
	"sort"
	"strconv"
	"strings"

	"github.com/device-management-toolkit/go-wsman-messages/v2/pkg/wsman/amt/boot"
	"github.com/device-management-toolkit/go-wsman-messages/v2/pkg/wsman/cim/power"
	"github.com/device-management-toolkit/go-wsman-messages/v2/pkg/wsman/cim/software"
	ipspower "github.com/device-management-toolkit/go-wsman-messages/v2/pkg/wsman/ips/power"
	"github.com/device-management-toolkit/rpc-go/v2/pkg/utils"
	log "github.com/sirupsen/logrus"
)

// The power commands mirror Console's power feature (console/internal/usecase/devices/power.go
// and console/internal/controller/mcp/power_actions.go) so a local agent sees the same action
// names, codes and behavior as a Console user, only executed against the local AMT over LMS/HECI.
const (
	// Console action codes that are not plain CIM RequestPowerStateChange values.
	osToFullPower   = 500
	osToPowerSaving = 501
	cimPowerOn      = int(power.PowerOn)

	// minAMTVersion matches Console's MinAMTVersion: soft-off, soft-reset, sleep and
	// hibernate are only offered on AMT versions newer than this.
	minAMTVersion = 9

	amtSoftwareInstanceID = "AMT"
)

// powerActionNames maps Console's MCP power action names to Console's action codes.
// Boot-target actions (BIOS, PXE, IDE-R, diagnostics, HTTPS boot) are excluded, as in
// Console, because they need the separate boot-configuration flow.
var powerActionNames = map[string]int{
	"power_on":           cimPowerOn,                        // CIM: verified hardware power on
	"sleep":              int(power.SleepDeep),              // CIM: sleep deep
	"power_cycle":        int(power.PowerCycleOffHard),      // CIM: power cycle (off then on)
	"hibernate":          int(power.Hibernate),              // CIM: hibernate
	"power_off":          int(power.PowerOffHard),           // CIM: verified hardware power off (hard)
	"power_off_soft":     int(power.PowerOffSoft),           // CIM: soft power off
	"reset":              int(power.MasterBusReset),         // CIM: master bus reset (reboot)
	"soft_off":           int(power.PowerOffSoftGraceful),   // CIM: soft off graceful
	"soft_reset":         int(power.MasterBusResetGraceful), // CIM: master bus reset graceful
	"os_to_full_power":   osToFullPower,                     // IPS: OS power saving -> full power
	"os_to_power_saving": osToPowerSaving,                   // IPS: OS full power -> power saving
}

var osPowerSavingStateNames = map[ipspower.OSPowerSavingState]string{
	ipspower.Unknown:       "Unknown",
	ipspower.Unsupported:   "Unsupported",
	ipspower.FullPower:     "FullPower",
	ipspower.OSPowerSaving: "OSPowerSaving",
}

// PowerCmd groups the power subcommands.
type PowerCmd struct {
	State        PowerStateCmd        `cmd:"" name:"state" help:"Show the AMT power state and the OS power-saving state"`
	Capabilities PowerCapabilitiesCmd `cmd:"" name:"capabilities" help:"List the power actions this device supports"`
	Action       PowerActionCmd       `cmd:"" name:"action" help:"Perform a power action on this device through AMT"`
}

// PowerStateResult is the output of `power state` (Console power_get_state).
type PowerStateResult struct {
	PowerState         int `json:"powerState"`
	OSPowerSavingState int `json:"osPowerSavingState"`
}

// PowerCapabilities uses the same JSON keys and codes as Console's GET power/capabilities.
type PowerCapabilities struct {
	PowerUp             int `json:"Power up,omitempty"`
	PowerCycle          int `json:"Power cycle,omitempty"`
	PowerDown           int `json:"Power down,omitempty"`
	Reset               int `json:"Reset,omitempty"`
	SoftOff             int `json:"Soft-off,omitempty"`
	SoftReset           int `json:"Soft-reset,omitempty"`
	Sleep               int `json:"Sleep,omitempty"`
	Hibernate           int `json:"Hibernate,omitempty"`
	PowerOnToBIOS       int `json:"Power up to BIOS,omitempty"`
	ResetToBIOS         int `json:"Reset to BIOS,omitempty"`
	ResetToSecureErase  int `json:"Reset to Secure Erase,omitempty"`
	ResetToIDERFloppy   int `json:"Reset to IDE-R Floppy,omitempty"`
	PowerOnToIDERFloppy int `json:"Power on to IDE-R Floppy,omitempty"`
	ResetToIDERCDROM    int `json:"Reset to IDE-R CDROM,omitempty"`
	PowerOnToIDERCDROM  int `json:"Power on to IDE-R CDROM,omitempty"`
	PowerOnToDiagnostic int `json:"Power on to diagnostic,omitempty"`
	ResetToDiagnostic   int `json:"Reset to diagnostic,omitempty"`
	ResetToPXE          int `json:"Reset to PXE,omitempty"`
	PowerOnToPXE        int `json:"Power on to PXE,omitempty"`
}

// PowerCapabilitiesResult is the output of `power capabilities`: the action names usable
// with `power action` (Console power_get_capabilities) plus Console's raw capability codes.
type PowerCapabilitiesResult struct {
	SupportedActions []string          `json:"supportedActions"`
	Capabilities     PowerCapabilities `json:"capabilities"`
}

// PowerActionResult is the output of `power action` (Console power_action).
type PowerActionResult struct {
	Action      string `json:"action"`
	Code        int    `json:"code"`
	ReturnValue int    `json:"returnValue"`
}

// PowerStateCmd reports the power state.
type PowerStateCmd struct {
	AMTBaseCmd
}

// Run executes the power state command.
func (cmd *PowerStateCmd) Run(ctx *Context) error {
	if err := ensurePowerRuntime(ctx, &cmd.AMTBaseCmd); err != nil {
		return err
	}

	items, err := cmd.WSMan.GetPowerState()
	if err != nil {
		return wsmanError(err)
	}

	if len(items) == 0 {
		return wsmanError(fmt.Errorf("GetPowerState returned empty state"))
	}

	osState, err := cmd.WSMan.GetOSPowerSavingState()
	if err != nil {
		return wsmanError(err)
	}

	result := PowerStateResult{PowerState: int(items[0].PowerState), OSPowerSavingState: int(osState)}

	return writePowerOutput(os.Stdout, ctx.JsonOutput, result, func(w io.Writer) {
		fmt.Fprint(w, renderInfoHeader("POWER STATE"))
		fmt.Fprint(w, renderInfoRow("Power State", fmt.Sprintf("%d (%s)", result.PowerState, items[0].PowerState.String())))
		fmt.Fprint(w, renderInfoRow("OS Power Saving", fmt.Sprintf("%d (%s)", result.OSPowerSavingState, osPowerSavingStateNames[osState])))
		fmt.Fprintln(w)
	})
}

// PowerCapabilitiesCmd lists the supported power actions.
type PowerCapabilitiesCmd struct {
	AMTBaseCmd
}

// Run executes the power capabilities command.
func (cmd *PowerCapabilitiesCmd) Run(ctx *Context) error {
	if err := ensurePowerRuntime(ctx, &cmd.AMTBaseCmd); err != nil {
		return err
	}

	version, err := cmd.WSMan.GetAMTVersion()
	if err != nil {
		return wsmanError(err)
	}

	bootCapabilities, err := cmd.WSMan.GetBootCapabilities()
	if err != nil {
		return wsmanError(err)
	}

	amtVersion, err := parseAMTMajorVersion(version)
	if err != nil {
		return wsmanError(err)
	}

	capabilities := determinePowerCapabilities(amtVersion, bootCapabilities)
	result := PowerCapabilitiesResult{SupportedActions: capabilityActionNames(capabilities), Capabilities: capabilities}

	return writePowerOutput(os.Stdout, ctx.JsonOutput, result, func(w io.Writer) {
		fmt.Fprint(w, renderInfoHeader("POWER CAPABILITIES"))
		fmt.Fprint(w, renderInfoRow("Supported Actions", strings.Join(result.SupportedActions, ", ")))
		fmt.Fprintln(w)
	})
}

// PowerActionCmd performs a power action.
type PowerActionCmd struct {
	AMTBaseCmd
	Action string `help:"Power action to perform" name:"action" required:"" enum:"power_on,sleep,power_cycle,hibernate,power_off,power_off_soft,reset,soft_off,soft_reset,os_to_full_power,os_to_power_saving"`
}

// Run executes the power action command.
func (cmd *PowerActionCmd) Run(ctx *Context) error {
	if err := ensurePowerRuntime(ctx, &cmd.AMTBaseCmd); err != nil {
		return err
	}

	code, ok := powerActionNames[cmd.Action]
	if !ok {
		return utils.CustomError{Code: utils.InvalidUserInput.Code, Message: utils.InvalidUserInput.Message, Details: "unknown power action: " + cmd.Action}
	}

	log.Infof("requesting power action %s (%d)", cmd.Action, code)

	returnValue, err := sendPowerAction(&cmd.AMTBaseCmd, code)
	if err != nil {
		return wsmanError(err)
	}

	if returnValue != 0 {
		return utils.CustomError{
			Code:    utils.WSMANMessageError.Code,
			Message: utils.WSMANMessageError.Message,
			Details: fmt.Sprintf("power action %s returned %s (%d)", cmd.Action, power.ReturnValue(returnValue).String(), returnValue),
		}
	}

	result := PowerActionResult{Action: cmd.Action, Code: code, ReturnValue: returnValue}

	return writePowerOutput(os.Stdout, ctx.JsonOutput, result, func(w io.Writer) {
		fmt.Fprint(w, renderInfoHeader("POWER ACTION"))
		fmt.Fprint(w, renderInfoRow("Action", fmt.Sprintf("%s (%d)", result.Action, result.Code)))
		fmt.Fprint(w, renderInfoRow("Return Value", strconv.Itoa(result.ReturnValue)))
		fmt.Fprintln(w)
	})
}

// sendPowerAction follows Console's SendPowerAction: 500/501 change the OS power-saving
// state through IPS_PowerManagementService, power on first brings the OS to full power,
// and every other code is sent as-is to CIM_PowerManagementService.RequestPowerStateChange.
func sendPowerAction(base *AMTBaseCmd, code int) (int, error) {
	if code == osToFullPower || code == osToPowerSaving {
		return changeOSPowerSavingState(base, code)
	}

	if code == cimPowerOn {
		if _, err := changeOSPowerSavingState(base, osToFullPower); err != nil {
			return 0, err
		}
	}

	response, err := base.WSMan.RequestPowerStateChange(power.PowerState(code))
	if err != nil {
		return 0, err
	}

	return int(response.Body.RequestPowerStateChangeResponse.ReturnValue), nil
}

// changeOSPowerSavingState mirrors Console's handleOSPowerSavingStateChange: it is a no-op
// (return value 0) when the OS is already in the target state.
func changeOSPowerSavingState(base *AMTBaseCmd, code int) (int, error) {
	target := ipspower.OSPowerSaving
	if code == osToFullPower {
		target = ipspower.FullPower
	}

	current, err := base.WSMan.GetOSPowerSavingState()
	if err != nil {
		return 0, err
	}

	if current == target {
		return 0, nil
	}

	response, err := base.WSMan.RequestOSPowerSavingStateChange(target)
	if err != nil {
		return 0, err
	}

	return int(response.ReturnValue), nil
}

// determinePowerCapabilities is Console's determinePowerCapabilities.
func determinePowerCapabilities(amtVersion int, capabilities boot.BootCapabilitiesResponse) PowerCapabilities {
	response := PowerCapabilities{
		PowerUp:    cimPowerOn,
		PowerCycle: int(power.PowerCycleOffHard),
		PowerDown:  int(power.PowerOffHard),
		Reset:      int(power.MasterBusReset),
	}

	if amtVersion > minAMTVersion {
		response.SoftOff = int(power.PowerOffSoftGraceful)
		response.SoftReset = int(power.MasterBusResetGraceful)
		response.Sleep = int(power.SleepDeep)
		response.Hibernate = int(power.Hibernate)
	}

	if capabilities.BIOSSetup {
		response.PowerOnToBIOS = 100
		response.ResetToBIOS = 101
	}

	if capabilities.SecureErase {
		response.ResetToSecureErase = 104
	}

	response.ResetToIDERFloppy = 200
	response.PowerOnToIDERFloppy = 201
	response.ResetToIDERCDROM = 202
	response.PowerOnToIDERCDROM = 203

	if capabilities.ForceDiagnosticBoot {
		response.PowerOnToDiagnostic = 300
		response.ResetToDiagnostic = 301
	}

	response.ResetToPXE = 400
	response.PowerOnToPXE = 401

	return response
}

// capabilityActionNames mirrors Console's MCP capabilityActionNames: the power_action
// names whose codes the device reports as supported.
func capabilityActionNames(caps PowerCapabilities) []string {
	codeToName := make(map[int]string, len(powerActionNames))
	for name, code := range powerActionNames {
		codeToName[code] = name
	}

	codes := []int{caps.PowerUp, caps.PowerCycle, caps.PowerDown, caps.Reset, caps.SoftOff, caps.SoftReset, caps.Sleep, caps.Hibernate}
	names := make([]string, 0, len(codes))

	for _, code := range codes {
		if name, ok := codeToName[code]; ok && code != 0 {
			names = append(names, name)
		}
	}

	sort.Strings(names)

	return names
}

// parseAMTMajorVersion mirrors Console's parseVersion: the major number of the
// CIM_SoftwareIdentity instance whose InstanceID is "AMT".
func parseAMTMajorVersion(identities []software.SoftwareIdentity) (int, error) {
	major := 0

	for _, identity := range identities {
		if identity.InstanceID != amtSoftwareInstanceID {
			continue
		}

		v, err := strconv.Atoi(strings.Split(identity.VersionString, ".")[0])
		if err != nil {
			return 0, err
		}

		major = v
	}

	return major, nil
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

func wsmanError(err error) error {
	return utils.CustomError{Code: utils.WSMANMessageError.Code, Message: utils.WSMANMessageError.Message, Details: err.Error()}
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
