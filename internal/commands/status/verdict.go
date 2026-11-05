/*********************************************************************
 * Copyright (c) Intel Corporation 2026
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/

package status

import "strings"

// EvaluateVerdict is the sole readiness decision point used by all output formats.
func EvaluateVerdict(checks []Check) Verdict {
	postActivation := false
	remoteNetworkReady := remoteActivationNetworkReady(checks)

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
			if !postActivation && check.ID == checkIDHostNetwork {
				continue
			}

			if postActivation {
				return Verdict{Result: resultNotReady, Status: "Device is not ready for remote management"}
			}

			return Verdict{Result: resultNotReady, Status: "Device is not ready for the selected activation profile"}
		}
	}

	for _, check := range checks {
		if !postActivation && check.ID == checkIDAdmin && check.Status == checkUnavailable {
			return Verdict{Result: resultUnknown, Status: "AMT status unknown (run as administrator)"}
		}
	}

	for _, check := range checks {
		if check.Status == checkUnavailable || check.Status == checkNotEvaluated {
			if !postActivation && check.ID == checkIDHostNetwork {
				continue
			}

			if postActivation && (check.ID == checkIDDirectHost || check.ID == checkIDMonitor) {
				continue
			}

			if postActivation {
				return unverifiedManagementVerdict(checks)
			}

			return Verdict{Result: resultUnknown, Status: "AMT readiness is unknown because required checks could not run"}
		}
	}

	if !postActivation {
		for _, check := range checks {
			if check.ID == checkIDHostNetwork && check.Reason == reasonRemoteNetworkBlocked {
				return Verdict{Result: resultConditional, Status: "Local activation only; RPS/Console-profile activation is blocked by host networking", ReadyToProvision: true, Reason: reasonRemoteNetworkBlocked}
			}
		}

		for _, check := range checks {
			if check.ID == checkIDNetwork && check.Reason == reasonLocalOnlyNetwork {
				return Verdict{Result: resultConditional, Status: "CCM can proceed locally; remote activation requires an AMT network link", ReadyToProvision: true, Reason: reasonLocalOnlyNetwork}
			}
		}

		for _, check := range checks {
			if check.ID == checkIDDNS && check.Status == checkWarn && check.Reason == reasonDNSSuffixMismatch {
				return Verdict{
					Result:                   resultConditional,
					Status:                   "Device is conditionally ready; AMT and host DNS suffixes differ",
					ReadyToProvision:         true,
					ReadyForRemoteActivation: remoteNetworkReady,
					Reason:                   reasonDNSSuffixMismatch,
				}
			}
		}
	}

	for _, check := range checks {
		if check.Status == checkWarn {
			if postActivation {
				return Verdict{Result: resultReady, Status: "Device is fully configured and ready for remote management; review warnings", ReadyForManagement: true}
			}

			return Verdict{Result: resultConditional, Status: "Device is conditionally ready; review warnings", ReadyToProvision: true, ReadyForRemoteActivation: remoteNetworkReady}
		}
	}

	if postActivation {
		return Verdict{Result: resultReady, Status: "Device is fully configured and ready for remote management", ReadyForManagement: true}
	}

	if !remoteNetworkReady {
		return Verdict{Result: resultReady, Status: "Device is ready for local activation; remote activation readiness could not be verified", ReadyToProvision: true}
	}

	return Verdict{Result: resultReady, Status: "Device is ready for activation", ReadyToProvision: true, ReadyForRemoteActivation: true}
}

func remoteActivationNetworkReady(checks []Check) bool {
	for _, check := range checks {
		if check.ID == checkIDHostNetwork {
			return check.Status == checkPass
		}
	}

	return false
}

func unverifiedManagementVerdict(checks []Check) Verdict {
	var reasons []string

	for _, check := range checks {
		if check.Status != checkUnavailable && check.Status != checkNotEvaluated {
			continue
		}

		if check.ID == checkIDDirectHost || check.ID == checkIDMonitor {
			continue
		}

		reason := strings.TrimSpace(check.Message)
		if reason == "" {
			reason = check.Name
		}

		if reason == "" {
			reason = check.ID
		}

		reasons = append(reasons, reason)
	}

	return Verdict{Result: resultUnknown, Status: "Activated; management features not verified: " + strings.Join(reasons, "; ")}
}
