/*********************************************************************
 * Copyright (c) Intel Corporation 2021
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/
package configure

import (
	"errors"
	"fmt"

	"github.com/device-management-toolkit/go-wsman-messages/v2/pkg/wsman/ips/ieee8021x"
	"github.com/device-management-toolkit/rpc-go/v2/pkg/utils"
)

// Error messages
var (
	// ErrDeviceNotActivated indicates the device is not activated and cannot be
	// configured. It is a utils.CustomError so that subprocess invocations exit
	// with a distinct code (DeviceNotActivated) the orchestrator can match on,
	// rather than the generic failure code — see orchestrator.isDeviceNotActivatedErr.
	ErrDeviceNotActivated = utils.DeviceNotActivated

	// ErrMPSCertRequired indicates CIRA was requested without an MPS root certificate.
	ErrMPSCertRequired = errors.New("MPS root certificate is required")
)

// validateIEEE8021xAuthenticationProtocol mirrors the Kong enum (0=EAP-TLS,
// 2=PEAPv0/EAP-MSCHAPv2) for callers that construct commands without Kong.
func validateIEEE8021xAuthenticationProtocol(protocol int) error {
	switch protocol {
	case ieee8021x.AuthenticationProtocolEAPTLS, ieee8021x.AuthenticationProtocolPEAPv0_EAPMSCHAPv2:
		return nil
	default:
		return fmt.Errorf("invalid IEEE 802.1x authentication protocol %d: must be 0 (EAP-TLS) or 2 (PEAPv0/EAP-MSCHAPv2)", protocol)
	}
}
