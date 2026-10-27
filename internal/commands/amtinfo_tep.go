/*********************************************************************
 * Copyright (c) Intel Corporation 2026
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/

package commands

import (
	"errors"
	"strconv"
	"strings"
	"time"

	"github.com/device-management-toolkit/rpc-go/v2/pkg/mkhi"
	"github.com/device-management-toolkit/rpc-go/v2/pkg/upid"
	log "github.com/sirupsen/logrus"
)

const (
	// tepVoucherNone is the voucher status when no voucher is installed for a feature.
	tepVoucherNone = "none"

	tepSectionTitle = "Intel Trusted Endpoint Provisioning (TEP)"
	tepFlag         = "--tep"

	tepSupportedLabel = "Supported"
)

// TEPInfo is the Intel Trusted Endpoint Provisioning (TEP) status of the device.
type TEPInfo struct {
	// Supported is true on CSME 18 or later with the TEP firmware capability.
	Supported bool `json:"supported"`
	// Unavailable is the short reason the TEP status could not be fully read.
	Unavailable string `json:"unavailable,omitempty"`
	// MaxVouchers is the number of ownership vouchers CSME can hold.
	MaxVouchers int `json:"maxVouchers,omitempty"`
	// Features lists the features that can be provisioned through TEP.
	Features []string `json:"features,omitempty"`
	// Vouchers holds the ownership voucher state of each feature.
	Vouchers []TEPVoucher `json:"vouchers,omitempty"`
	// LastACMAttempt is the result of the latest host-based ACM provisioning
	// attempt, including TEP-specific failure reasons.
	LastACMAttempt string `json:"lastAcmAttempt,omitempty"`
}

// TEPVoucher is the ownership voucher state of one TEP feature.
type TEPVoucher struct {
	Feature string `json:"feature"`
	// Status is the ownership status ("active", "requested", ...), "none" when
	// no voucher is installed for the feature, or "unknown" when it could not be read.
	Status    string `json:"status"`
	VoucherID string `json:"voucherId,omitempty"`
	OwnerID   string `json:"ownerId,omitempty"`
	// OwnershipExpires is when ownership expires, in RFC 3339 format (UTC).
	OwnershipExpires string `json:"ownershipExpires,omitempty"`
	// OwnershipService is the subject of the Ownership Service certificate.
	OwnershipService string `json:"ownershipService,omitempty"`
}

// tepVersionReadTimeout matches the timeout amtinfo uses for its other version reads.
const tepVersionReadTimeout = 2 * time.Minute

// addTEPInfo sets result.TEP. TEP support depends on the CSME version, so it
// reads the version when amtinfo has not already tried to. It does not set
// result.AMT, so the version only appears in the output when it was asked for.
func (s *InfoService) addTEPInfo(result *InfoResult, cmd *AmtInfoCmd, showAll bool) {
	if !s.heciAvailable {
		return
	}

	amtVersion := result.AMT
	if amtVersion == "" && !showAll && !cmd.Ver && !cmd.OpState {
		version, err := s.amtCommand.GetVersionDataFromME("AMT", tepVersionReadTimeout)
		if err != nil {
			log.Debug("TEP: could not read the AMT version: ", err)
		}

		amtVersion = version
	}

	result.TEP = s.getTEPInfo(amtVersion, cmd.TEP)
}

// getTEPInfo reads the TEP status. When the device cannot support TEP, or
// the support check fails, it returns nil unless explicit (--tep) is set, so
// the default output does not change on older devices. It checks the CSME
// version before reading anything, so devices older than CSME 18 make no
// extra HECI calls.
func (s *InfoService) getTEPInfo(amtVersion string, explicit bool) *TEPInfo {
	notSupported := func(info *TEPInfo) *TEPInfo {
		if explicit {
			return info
		}

		return nil
	}

	major, err := s.getMajorVersion(amtVersion)
	if err != nil {
		log.Debug("TEP: could not read the CSME version: ", err)

		return notSupported(&TEPInfo{Unavailable: "CSME version could not be read"})
	}

	if major < mkhi.MinTEPCSMEMajor {
		return notSupported(&TEPInfo{})
	}

	caps, err := s.amtCommand.GetFWCapabilities()
	if err != nil {
		log.Debug("TEP: could not read firmware capabilities: ", err)

		return notSupported(&TEPInfo{Unavailable: "firmware capabilities could not be read"})
	}

	if !mkhi.TEPSupported(major, caps) {
		return notSupported(&TEPInfo{})
	}

	info := &TEPInfo{Supported: true}

	tepCaps, err := s.amtCommand.TEPGetCapabilities()
	if err != nil {
		log.Debug("TEP: could not read TEP capabilities: ", err)

		info.Unavailable = "TEP capabilities could not be read"

		return info
	}

	info.MaxVouchers = tepCaps.MaxVouchers

	for _, feature := range tepCaps.Features {
		info.Features = append(info.Features, feature.String())
		info.Vouchers = append(info.Vouchers, s.getTEPVoucher(feature))
	}

	provLog, err := s.amtCommand.GetProvisioningLog()
	if err != nil {
		log.Debug("TEP: could not read the provisioning log: ", err)
	} else {
		info.LastACMAttempt = provLog.AcmProvisioningStatus.String()
	}

	return info
}

// getTEPVoucher reads the ownership voucher state of one feature.
func (s *InfoService) getTEPVoucher(feature upid.TEPFeature) TEPVoucher {
	voucher := TEPVoucher{Feature: feature.String(), Status: tepVoucherNone}

	state, err := s.amtCommand.TEPGetVoucherStateByFeature(feature)
	if errors.Is(err, upid.ErrTEPInvalidVoucher) {
		// CSME answers TEP_INVALID_VOUCHER when no voucher is installed for the feature.
		return voucher
	}

	if err != nil {
		log.Debug("TEP: could not read the ", feature, " voucher state: ", err)

		voucher.Status = statusUnknown

		return voucher
	}

	ctx := state.Context
	if ctx.OwnershipStatus == upid.TEPOwnershipNotSet {
		return voucher
	}

	voucher.Status = ctx.OwnershipStatus.String()
	voucher.VoucherID = ctx.VoucherID.String()
	voucher.OwnerID = ctx.OwnerID.String()

	if ctx.OwnershipExpiresOnUTC != 0 {
		voucher.OwnershipExpires = time.Unix(int64(ctx.OwnershipExpiresOnUTC), 0).UTC().Format(time.RFC3339)
	}

	if name, err := ctx.SubjectName(); err != nil {
		log.Debug("TEP: could not decode the Ownership Service certificate subject: ", err)
	} else {
		voucher.OwnershipService = name.String()
	}

	return voucher
}

// infoRow is one label/value line of an amtinfo section.
type infoRow struct {
	label, value string
	// unavailable marks value as the reason the field could not be read.
	unavailable bool
}

// tepRows lists the rows of the TEP section, shared by the text and table output.
func tepRows(tep *TEPInfo) []infoRow {
	if !tep.Supported {
		if tep.Unavailable != "" {
			return []infoRow{{label: tepSupportedLabel, value: tep.Unavailable, unavailable: true}}
		}

		return []infoRow{{label: tepSupportedLabel, value: "No"}}
	}

	rows := []infoRow{{label: tepSupportedLabel, value: "Yes"}}

	if tep.Unavailable != "" {
		return append(rows, infoRow{label: "Vouchers", value: tep.Unavailable, unavailable: true})
	}

	rows = append(rows,
		infoRow{label: "Max Vouchers", value: strconv.Itoa(tep.MaxVouchers)},
		infoRow{label: "Features", value: strings.Join(tep.Features, ", ")},
	)

	for _, v := range tep.Vouchers {
		rows = append(rows, infoRow{label: v.Feature + " Voucher", value: v.Status})

		for _, detail := range []struct{ label, value string }{
			{"Voucher ID", v.VoucherID},
			{"Owner ID", v.OwnerID},
			{"Ownership Expires", v.OwnershipExpires},
			{"Ownership Service", v.OwnershipService},
		} {
			if detail.value != "" {
				rows = append(rows, infoRow{label: v.Feature + " " + detail.label, value: detail.value})
			}
		}
	}

	if tep.LastACMAttempt != "" {
		rows = append(rows, infoRow{label: "Last ACM Attempt", value: tep.LastACMAttempt})
	}

	return rows
}

// buildTEPSection renders the Intel TEP block of the text output.
func buildTEPSection(result *InfoResult, cmd *AmtInfoCmd, showAll bool) string {
	if (!showAll && !cmd.TEP) || result.TEP == nil {
		return ""
	}

	var b strings.Builder

	b.WriteString(renderInfoHeader(tepSectionTitle))

	for _, row := range tepRows(result.TEP) {
		if row.unavailable {
			b.WriteString(renderUnavailableRow(row.label, row.value))
		} else {
			b.WriteString(renderInfoRow(row.label, row.value))
		}
	}

	return b.String()
}
