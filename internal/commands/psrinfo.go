/*********************************************************************
 * Copyright (c) Intel Corporation 2026
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/

package commands

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"

	"github.com/device-management-toolkit/rpc-go/v2/pkg/psr"
	log "github.com/sirupsen/logrus"
)

// psrFilePerm / psrDirPerm mirror the permissions used by the CSME flash-log
// dump in internal/commands/diagnostics/csme.go.
const (
	psrFilePerm = 0o644
	psrDirPerm  = 0o755
)

// PSRInfoCmd displays the Intel Platform Service Record (PSR).
//
// PSR is a CSME-level feature rather than an AMT one: it is readable on
// platforms where AMT was never provisioned or is disabled outright. The
// command therefore requires neither WSMAN nor an AMT password. It does
// require elevation: PSR is read over HECI, so unlike amtinfo there is no
// useful degraded mode, and SkipWSMANSetup is deliberately left unset so that
// an unelevated run returns utils.IncorrectPermissions and cli.Execute can
// offer to self-elevate.
type PSRInfoCmd struct {
	AMTBaseCmd

	Output string `help:"Write the signed PSR blob to this file" short:"o"`
	Verify bool   `help:"Verify the PSR signature and certificate chain"`
}

// psrInfoOutput is the JSON representation of a psrinfo run.
type psrInfoOutput struct {
	Status       uint32 `json:"status"`
	PayloadBytes int    `json:"payloadBytes"`
	TotalBytes   int    `json:"totalBytes"`
	Nonce        string `json:"nonce"`
	Verified     *bool  `json:"verified,omitempty"`
	OutputFile   string `json:"outputFile,omitempty"`
}

// RequiresAMTPassword indicates whether this command requires an AMT password.
// PSR is read over its own MEI client and never authenticates to AMT.
func (cmd *PSRInfoCmd) RequiresAMTPassword() bool {
	return false
}

// Run executes the psrinfo command.
func (cmd *PSRInfoCmd) Run(ctx *Context) error {
	log.Debug("Starting PSR retrieval")

	record, err := ctx.AMTCommand.GetPSR()
	if err != nil {
		return describeRetrievalError(err)
	}

	if record == nil {
		return fmt.Errorf("%w: no record returned", psr.ErrInvalidResponse)
	}

	out := psrInfoOutput{
		Status:       record.Status,
		PayloadBytes: len(record.Payload),
		TotalBytes:   len(record.Raw),
		Nonce:        hex.EncodeToString(record.UserNonce),
	}

	if cmd.Verify {
		verifyErr := record.VerifySignature()
		if verifyErr != nil {
			return fmt.Errorf("failed to verify PSR: %w", verifyErr)
		}

		verified := true
		out.Verified = &verified
	}

	if cmd.Output != "" {
		if err := writePSRBlob(cmd.Output, record.Raw); err != nil {
			return err
		}

		out.OutputFile = cmd.Output
	}

	return renderPSRInfo(ctx, out)
}

// describeRetrievalError turns a PSR retrieval failure into an actionable
// message. Unavailability is an expected outcome on most platforms, so it is
// reported plainly rather than as an opaque HECI error.
func describeRetrievalError(err error) error {
	switch {
	case errors.Is(err, psr.ErrPSRGUIDNotConfigured):
		return fmt.Errorf("%w: this build has no PSR MEI client GUID compiled in", err)
	case errors.Is(err, psr.ErrPSRNotSupported):
		return fmt.Errorf("%w: Intel PSR requires CSME 16.1 or later and must be enabled by the OEM", err)
	default:
		return fmt.Errorf("failed to retrieve PSR: %w", err)
	}
}

// writePSRBlob persists the raw signed record to disk.
func writePSRBlob(path string, blob []byte) error {
	outputDir := filepath.Dir(path)
	if outputDir != "." && outputDir != "" {
		if err := os.MkdirAll(outputDir, psrDirPerm); err != nil {
			return fmt.Errorf("failed to create output directory: %w", err)
		}
	}

	if err := os.WriteFile(path, blob, psrFilePerm); err != nil {
		return fmt.Errorf("failed to write PSR file: %w", err)
	}

	return nil
}

// renderPSRInfo prints the retrieved record as JSON or as a summary table.
func renderPSRInfo(ctx *Context, out psrInfoOutput) error {
	if ctx.JsonOutput {
		outBytes, err := json.MarshalIndent(out, "", "  ")
		if err != nil {
			return fmt.Errorf("failed to encode PSR output: %w", err)
		}

		fmt.Println(string(outBytes))

		return nil
	}

	fmt.Print(renderInfoHeader("Intel PSR"))
	fmt.Print(renderInfoRow("Status", strconv.FormatUint(uint64(out.Status), 10)))
	fmt.Print(renderInfoRow("Record Size", strconv.Itoa(out.TotalBytes)+" bytes"))
	fmt.Print(renderInfoRow("Nonce", out.Nonce))

	if out.Verified != nil {
		fmt.Print(renderInfoRow("Signature", "Verified"))
	}

	if out.OutputFile != "" {
		fmt.Print(renderInfoRow("Saved To", out.OutputFile))
	}

	// Field-level decoding (uptime, boot and reset counters, chassis intrusion
	// and sanitization events) arrives with psr.PSR.ParseRecord.
	fmt.Print(renderInfoRow("Detail", "record field decoding not yet implemented"))
	fmt.Println()

	return nil
}
