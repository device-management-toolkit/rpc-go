/*********************************************************************
 * Copyright (c) Intel Corporation 2026
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/

package status

import "strings"

// EvaluateVerdict is the sole readiness decision point used by all output formats.
func EvaluateVerdict(checks []Check) Verdict {
	postActivation := false

	for _, check := range checks {
		if check.ID == checkIDWSMAN {
			postActivation = true

			break
		}
	}

	for _, check := range checks {
		if check.Status == checkAlreadyActive && !postActivation {
			return Verdict{
				Result: "not_evaluated",
				Status: "AMT is already activated; post-activation health was not evaluated",
			}
		}
	}

	for _, check := range checks {
		if check.ID == checkIDMEI && check.Status == checkFail {
			return Verdict{Result: resultNotAMT, Status: "AMT/MEI device was not detected"}
		}
	}

	for _, check := range checks {
		if check.Status == checkFail {
			if postActivation {
				return Verdict{Result: resultNotReady, Status: "Device is not ready for remote management"}
			}

			return Verdict{Result: resultNotReady, Status: "Device is not ready for the selected activation profile"}
		}
	}

	for _, check := range checks {
		if check.ID == checkIDAdmin && check.Status == checkUnavailable {
			return Verdict{Result: resultUnknown, Status: "AMT status unknown (run as administrator)"}
		}
	}

	for _, check := range checks {
		if check.Status == checkUnavailable || check.Status == checkNotEvaluated {
			if postActivation && (check.ID == checkIDDirectHost || check.ID == checkIDMonitor) {
				continue
			}

			return Verdict{Result: resultUnknown, Status: "AMT readiness is unknown because required checks could not run"}
		}
	}

	if !postActivation {
		for _, check := range checks {
			if check.ID == checkIDDNS && check.Status == checkWarn && strings.HasPrefix(strings.TrimSpace(check.Message), "AMT DNS suffix (") {
				return Verdict{
					Result:           resultConditional,
					Status:           "Device is conditionally ready; AMT and host DNS suffixes differ",
					ReadyToProvision: true,
				}
			}
		}
	}

	for _, check := range checks {
		if check.Status == checkWarn {
			if postActivation {
				return Verdict{Result: resultReady, Status: "Device is fully configured and ready for remote management; review warnings", ReadyForManagement: true}
			}

			return Verdict{Result: resultConditional, Status: "Device is conditionally ready; review warnings", ReadyToProvision: true}
		}
	}

	if postActivation {
		return Verdict{Result: resultReady, Status: "Device is fully configured and ready for remote management", ReadyForManagement: true}
	}

	return Verdict{Result: resultReady, Status: "Device is ready for activation", ReadyToProvision: true}
}
