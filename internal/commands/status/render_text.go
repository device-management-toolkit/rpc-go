/*********************************************************************
 * Copyright (c) Intel Corporation 2026
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/

package status

import (
	"fmt"
	"io"
	"strings"
)

func renderText(w io.Writer, result report) error {
	var output strings.Builder
	output.WriteString("  AMT Health Check\n")
	output.WriteString("  ────────────────\n")
	fmt.Fprintf(&output, "  Detected state: %s\n", displayDetectedState(result.DetectedState))
	fmt.Fprintf(&output, "  Selected checks: %s\n\n", displayCheckSet(result.SelectedCheckSet))

	sections := []struct {
		title  string
		states []checkState
	}{
		{title: "Passed", states: []checkState{checkPass}},
		{title: "Warnings", states: []checkState{checkWarn}},
		{title: "Failed", states: []checkState{checkFail}},
		{title: "Not verified", states: []checkState{checkUnavailable, checkNotEvaluated, checkAlreadyActive}},
	}

	for _, section := range sections {
		var rows []Check

		for _, check := range result.Checks {
			for _, state := range section.states {
				if check.Status == state {
					rows = append(rows, check)

					break
				}
			}
		}

		if len(rows) == 0 {
			continue
		}

		output.WriteString(section.title + "\n")

		for _, check := range rows {
			fmt.Fprintf(&output, "  %s %s\n", checkSymbol(check.Status), check.Message)
		}

		output.WriteByte('\n')
	}

	if len(result.ActivationProfiles) > 0 {
		output.WriteString("Activation profile readiness\n")

		for _, profile := range result.ActivationProfiles {
			fmt.Fprintf(&output, "  %s: %s\n", profile.Profile, readinessLabel(profile.Result))
		}

		output.WriteByte('\n')
	}

	fmt.Fprintf(&output, "%s %s\n", verdictSymbol(result.Verdict.Result), result.Verdict.Status)

	if result.Verdict.ReadyToProvision || len(result.ActivationProfiles) > 0 {
		output.WriteString(activationRecommendation(result) + "\n")
	} else {
		output.WriteString("→ Review the checks and re-run status after remediation.\n")
	}

	output.WriteString("\nSKU Information\n")
	writeInfoRow(&output, "Processor", fallback(result.ProcessorModel))
	writeInfoRow(&output, "Wired Adapter", adapterDisplay(result.WiredAdapterName, result.WiredAdapterStatus))
	writeInfoRow(&output, "Wireless Adapter", adapterDisplay(result.WirelessAdapterName, result.WirelessAdapterStatus))
	writeInfoRow(&output, "OS", fallback(result.OSDescription))

	if strings.TrimSpace(result.AMTOperationalState) == "" {
		output.WriteString("\nAMT Details\n")
		writeInfoRow(&output, "Operational state", "Not reported")
	}

	output.WriteString("\nAMT Connectivity\n")

	if result.RemoteAccess != nil {
		writeInfoRow(&output, "AMT-reported network status", connectivityValue(result.RemoteAccess.NetworkStatus))
		writeInfoRow(&output, "Remote access connection", connectivityValue(result.RemoteAccess.RemoteStatus))
		writeInfoRow(&output, "Remote access trigger", connectivityValue(result.RemoteAccess.RemoteTrigger))
	} else {
		writeInfoRow(&output, "AMT remote-access status", "Unavailable")
	}

	tlsMode := strings.TrimSpace(result.TLSMode)
	if tlsMode == "" {
		tlsMode = "Unavailable (WSMAN data unavailable)"
	}

	writeInfoRow(&output, "TLS mode", tlsMode)

	_, err := io.WriteString(w, output.String())

	return err
}

func activationRecommendation(result report) string {
	if len(result.ActivationProfiles) == 2 {
		acmReady := result.ActivationProfiles[0].ReadyToProvision
		ccmReady := result.ActivationProfiles[1].ReadyToProvision

		switch {
		case acmReady && ccmReady:
			if result.ActivationProfiles[0].Result == resultConditional || result.ActivationProfiles[1].Result == resultConditional {
				return "→ ACM or CCM can proceed conditionally; review warnings for your provisioning profile."
			}

			return "→ Device is ready for ACM or CCM activation."
		case acmReady:
			return "→ ACM can proceed; review the failed prerequisites before choosing CCM."
		case ccmReady:
			return "→ CCM can proceed; ACM has failed prerequisites listed above."
		default:
			if result.ActivationProfiles[0].Result == resultUnknown || result.ActivationProfiles[1].Result == resultUnknown {
				return "→ ACM and CCM readiness could not be determined; resolve unavailable checks above."
			}

			return "→ Neither ACM nor CCM is ready; address the failed or unavailable checks above."
		}
	}

	mode := "ACM or CCM"

	switch result.SelectedCheckSet {
	case checkSetPreACM:
		mode = "ACM"
	case checkSetPreCCM:
		mode = "CCM"
	}

	if result.Verdict.Result == resultConditional {
		if strings.Contains(result.Verdict.Status, "DNS suffixes differ") {
			return "→ Proceed with " + mode + " activation; verify the DNS suffix difference is compatible with the selected provisioning profile."
		}

		return "→ Proceed with " + mode + " activation if these warnings are acceptable."
	}

	return "→ Proceed with " + mode + " activation."
}

func readinessLabel(result string) string {
	switch result {
	case resultReady:
		return "Ready"
	case resultConditional:
		return "Conditionally ready"
	case resultNotReady, resultNotAMT:
		return "Not ready"
	default:
		return "Unknown"
	}
}

func displayDetectedState(state string) string {
	switch state {
	case "pre_provisioning":
		return "Pre-provisioning"
	case "admin control mode":
		return "Admin Control Mode"
	case "client control mode":
		return "Client Control Mode"
	case "amt_unavailable":
		return "AMT unavailable"
	case resultUnknown:
		return "Unknown"
	default:
		return state
	}
}

func displayCheckSet(checkSet string) string {
	switch checkSet {
	case checkSetPre:
		return "pre-activation"
	case checkSetPreACM:
		return "pre-activation (ACM profile)"
	case checkSetPreCCM:
		return "pre-activation (CCM profile)"
	case checkSetPost:
		return "post-activation"
	default:
		return strings.ReplaceAll(checkSet, "_", "-")
	}
}

func checkSymbol(state checkState) string {
	switch state {
	case checkPass:
		return "✓"
	case checkWarn:
		return "!"
	case checkFail:
		return "✗"
	case checkUnavailable, checkNotEvaluated, checkAlreadyActive:
		return "·"
	default:
		return "·"
	}
}

func verdictSymbol(result string) string {
	switch result {
	case "ready":
		return "✓"
	case resultConditional:
		return "!"
	case "not_ready", "not_amt":
		return "✗"
	default:
		return "·"
	}
}

func writeInfoRow(w io.Writer, label, value string) {
	fmt.Fprintf(w, "  %s: %s\n", label, value)
}

func fallback(value string) string {
	if strings.TrimSpace(value) == "" {
		return "Not detected"
	}

	return strings.TrimSpace(value)
}

func connectivityValue(value string) string {
	if strings.TrimSpace(value) == "" {
		return "Unavailable"
	}

	return strings.TrimSpace(value)
}

func adapterDisplay(name, status string) string {
	if strings.TrimSpace(status) == "" {
		status = "status not detected"
	}

	return fallback(name) + ", " + status
}
