/*********************************************************************
 * Copyright (c) Intel Corporation 2026
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/

package main

import (
	"fmt"
	"os"

	"github.com/device-management-toolkit/rpc-go/v2/pkg/configure"
)

func main() {
	password := os.Getenv("AMT_PASSWORD")
	opts := configure.BaseOptions{AMTPassword: password}

	fmt.Println("=== SyncClock ===")
	if err := configure.SyncClock(opts); err != nil {
		fmt.Fprintf(os.Stderr, "SyncClock: %v\n", err)
	}

	fmt.Println("=== SyncHostname ===")
	if err := configure.SyncHostname(opts); err != nil {
		fmt.Fprintf(os.Stderr, "SyncHostname: %v\n", err)
	}

	fmt.Println("=== EnableAMT ===")
	if err := configure.EnableAMT(opts); err != nil {
		fmt.Fprintf(os.Stderr, "EnableAMT: %v\n", err)
	}

	fmt.Println("=== DisableAMT ===")
	if err := configure.DisableAMT(opts); err != nil {
		fmt.Fprintf(os.Stderr, "DisableAMT: %v\n", err)
	}

	// Batch 2: Settings commands
	fmt.Println("=== ChangeAMTPassword ===")
	if err := configure.ChangeAMTPassword(configure.AMTPasswordOptions{
		BaseOptions: opts,
		NewPassword: os.Getenv("NEW_AMT_PASSWORD"),
	}); err != nil {
		fmt.Fprintf(os.Stderr, "ChangeAMTPassword: %v\n", err)
	}

	fmt.Println("=== SetMEBx ===")
	if err := configure.SetMEBx(configure.MEBxOptions{
		BaseOptions:  opts,
		MEBxPassword: os.Getenv("MEBX_PASSWORD"),
	}); err != nil {
		fmt.Fprintf(os.Stderr, "SetMEBx: %v\n", err)
	}

	fmt.Println("=== SetAMTFeatures ===")
	if err := configure.SetAMTFeatures(configure.AMTFeaturesOptions{
		BaseOptions: opts,
		KVM:         true,
		SOL:         true,
		IDER:        false,
		UserConsent: "all",
	}); err != nil {
		fmt.Fprintf(os.Stderr, "SetAMTFeatures: %v\n", err)
	}

	fmt.Println("=== ConfigureWiFiSync ===")
	if err := configure.ConfigureWiFiSync(configure.WiFiSyncOptions{
		BaseOptions:  opts,
		OSWiFiSync:   true,
		UEFIWiFiSync: true,
	}); err != nil {
		fmt.Fprintf(os.Stderr, "ConfigureWiFiSync: %v\n", err)
	}

	// Batch 3: Network commands
	fmt.Println("=== ConfigureWireless ===")
	if err := configure.ConfigureWireless(configure.WirelessOptions{
		BaseOptions:          opts,
		ProfileName:          "MyWiFi",
		SSID:                 "MySSID",
		Priority:             1,
		AuthenticationMethod: 6,
		EncryptionMethod:     4,
		PSKPassphrase:        "my-passphrase",
	}); err != nil {
		fmt.Fprintf(os.Stderr, "ConfigureWireless: %v\n", err)
	}

	fmt.Println("=== ConfigureWired ===")
	dhcp := true
	if err := configure.ConfigureWired(configure.WiredOptions{
		BaseOptions: opts,
		DHCPEnabled: &dhcp,
	}); err != nil {
		fmt.Fprintf(os.Stderr, "ConfigureWired: %v\n", err)
	}

	fmt.Println("=== ConfigureTLS ===")
	if err := configure.ConfigureTLS(configure.TLSOptions{
		BaseOptions: opts,
		Mode:        "Server",
	}); err != nil {
		fmt.Fprintf(os.Stderr, "ConfigureTLS: %v\n", err)
	}

	fmt.Println("=== ConfigureCIRA ===")
	if err := configure.ConfigureCIRA(configure.CIRAOptions{
		BaseOptions: opts,
		MPSAddress:  "https://mps.example.com",
		MPSCert:     "base64-cert-data",
	}); err != nil {
		fmt.Fprintf(os.Stderr, "ConfigureCIRA: %v\n", err)
	}

	fmt.Println("=== ConfigureProxy ===")
	if err := configure.ConfigureProxy(configure.ProxyOptions{
		BaseOptions: opts,
		List:        true,
	}); err != nil {
		fmt.Fprintf(os.Stderr, "ConfigureProxy: %v\n", err)
	}
}
