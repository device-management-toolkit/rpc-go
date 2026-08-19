/*********************************************************************
 * Copyright (c) Intel Corporation 2026
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/

package psr

import (
	"errors"
)

// Intel PSR (Platform Service Record) MEI client constants.
//
// PSR exposes a signed, tamper-resistant ledger of platform lifecycle data
// (uptime/S0 time, boot and reset counters, chassis intrusion events,
// sanitization events) over its own MEI/HECI client, in the same way UPID and
// HOTHAM do. See pkg/upid for the closest structural analog.
//
// Availability is gated: PSR requires Intel CSME 16.1 firmware or later AND
// explicit enablement by the OEM. Callers must treat ErrPSRNotSupported as an
// ordinary outcome, not a failure.
//
// Reference:
//   - https://www.intel.com/content/www/us/en/developer/articles/technical/platform-service-record-introduction.html
//   - https://www.intel.com/content/www/us/en/developer/articles/technical/platform-service-record-intel-mei-protocol.html
const (
	// PSRGUID is the Intel PSR MEI client GUID in Windows string form.
	//
	// UNVERIFIED — this value is not yet populated. Obtain it from the Intel
	// PSR sample application / SDK (https://www.intel.com/content/www/us/en/download/774587/)
	// and fill it in here, alongside MEIPSRGUID in linux.go. Until both are
	// set, GetPSR returns ErrPSRGUIDNotConfigured rather than attempting a
	// connection with a bogus client id.
	PSRGUID = ""

	// NonceSize is the length of the caller-supplied nonce echoed back in the
	// signed response. It provides freshness/anti-replay for attestation.
	NonceSize = 20
)

// PSR HECI command codes.
//
// UNVERIFIED — the documented protocol names the GET command
// (PSR_HECI_PLATFORM_SERVICE_RECORD_GET) but the numeric encoding must be
// confirmed against the Intel PSR sample application before this is trusted
// on the wire.
const (
	CommandGetPlatformServiceRecord uint32 = 1
)

// PSR HECI status codes.
//
// UNVERIFIED — only StatusSuccess is assumed here. Populate the remainder from
// the Intel PSR protocol documentation and extend mapStatusError accordingly.
const (
	StatusSuccess uint32 = 0
)

// Wire-format sizes.
//
// UNVERIFIED — HeaderSize and StatusSize reflect the documented shape of
// PSR_HECI_HEADER (Command, Reserved, Length) plus the response Status field.
// Confirm the exact field widths before relying on these offsets.
const (
	// HeaderSize is the encoded size of PSRHECIHeader in bytes.
	HeaderSize = 12
	// StatusSize is the encoded size of the response Status field in bytes.
	StatusSize = 4
	// MinResponseSize is the smallest response that can be meaningfully parsed.
	MinResponseSize = HeaderSize + StatusSize
)

// Common errors.
var (
	ErrPSRNotSupported        = errors.New("intel PSR is not supported on this platform (requires CSME 16.1+ and OEM enablement)")
	ErrPSRGUIDNotConfigured   = errors.New("intel PSR MEI client GUID is not configured in this build")
	ErrConnectionFailed       = errors.New("failed to connect to PSR MEI client")
	ErrCommandFailed          = errors.New("PSR command failed")
	ErrInvalidResponse        = errors.New("invalid response from PSR MEI client")
	ErrInvalidNonce           = errors.New("invalid nonce length")
	ErrNonceMismatch          = errors.New("PSR response nonce does not match the nonce sent")
	ErrRecordParsingNotImpl   = errors.New("PSR record field parsing is not implemented")
	ErrSignatureVerifyNotImpl = errors.New("PSR signature verification is not implemented")
)

// PSRHECIHeader is the header for Intel PSR MEI commands.
//
// UNVERIFIED field widths — see HeaderSize.
type PSRHECIHeader struct {
	Command  uint32
	Reserved uint32
	Length   uint32
}

// GetRecordRequest is a PSR_HECI_PLATFORM_SERVICE_RECORD_GET request.
type GetRecordRequest struct {
	Header    PSRHECIHeader
	UserNonce [NonceSize]byte
}

// PSR is a retrieved Platform Service Record.
//
// The documented response carries the header, status, PSR log state, PSR
// version, the record itself, a record hash, the user and CSME nonces, the
// firmware version, a signing mechanism, a signature, and a certificate chain.
//
// This skeleton parses only what can be validated without the exact on-wire
// layout: the header and status. Everything after the status is preserved
// verbatim in Payload so that field extraction can be added incrementally
// without changing the retrieval path. See ParseRecord.
type PSR struct {
	// Status is the PSR command status returned by CSME.
	Status uint32 `json:"status"`
	// Raw is the complete response as received, including the header.
	Raw []byte `json:"-"`
	// Payload is the response body following the header and status. It holds
	// the log state, version, record, hash, nonces, signature and certificates.
	Payload []byte `json:"-"`
	// UserNonce is the nonce supplied on the request, retained so a caller can
	// verify freshness once nonce extraction is implemented.
	UserNonce []byte `json:"-"`
}

// Interface defines the operations for Intel PSR.
type Interface interface {
	// GetPSR retrieves the signed Platform Service Record from the platform.
	// It returns ErrPSRNotSupported on platforms where PSR is unavailable.
	GetPSR() (*PSR, error)
}

// ParseRecord decodes the structured PSR fields out of p.Payload.
//
// Not yet implemented: it requires the verified on-wire layout from the Intel
// PSR sample application. It is the extension point for surfacing uptime, boot
// and reset counters, chassis intrusion events and sanitization events.
func (p *PSR) ParseRecord() error {
	return ErrRecordParsingNotImpl
}

// VerifySignature checks the PSR signature and certificate chain.
//
// Not yet implemented. Until it is, a retrieved PSR is display-only and must
// not be treated as attested. Trust anchors belong in internal/certs.
func (p *PSR) VerifySignature() error {
	return ErrSignatureVerifyNotImpl
}
