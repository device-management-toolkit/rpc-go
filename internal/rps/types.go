/*********************************************************************
 * Copyright (c) Intel Corporation 2025
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/
package rps

import "time"

// IPConfiguration represents device network configuration settings included in RPS payloads.
type IPConfiguration struct {
	DHCP         bool   `json:"dhcp"`
	Static       bool   `json:"static"`
	IpSync       bool   `json:"ipsync"`
	IpAddress    string `json:"ipAddress"`
	Netmask      string `json:"netmask"`
	Gateway      string `json:"gateway"`
	PrimaryDns   string `json:"primaryDns"`
	SecondaryDns string `json:"secondaryDns"`
}

// HostnameInfo contains optional hostname related fields included in RPS payloads.
type HostnameInfo struct {
	DnsSuffixOS string `json:"dnsSuffixOS"`
	Hostname    string `json:"hostname"`
}

// Request contains all inputs required by RPS execution and payload creation.
// This replaces the usage of the former internal/flags.Flags structure for RPS flows.
type Request struct {
	// Command selection and modifiers
	Command        string
	SubCommand     string
	Profile        string
	Password       string
	StaticPassword string
	Force          bool

	// Connection and server parameters
	URL              string
	Proxy            string
	LocalTlsEnforced bool
	SkipAmtCertCheck bool
	ControlMode      int
	SkipCertCheck    bool

	// Device/payload fields
	DNS                string
	Hostname           string
	AMTTimeoutDuration time.Duration
	TenantID           string
	IpConfiguration    IPConfiguration
	HostnameInfo       HostnameInfo
	UUID               string
	FriendlyName       string

	// Logging/output preferences (forwarded to commands when applicable)
	LogLevel   string
	JsonOutput bool
	Verbose    bool
}
