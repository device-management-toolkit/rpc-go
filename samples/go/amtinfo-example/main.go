/*********************************************************************
 * Copyright (c) Intel Corporation 2026
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/

package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"

	"github.com/device-management-toolkit/rpc-go/v2/pkg/amtinfo"
	"github.com/device-management-toolkit/rpc-go/v2/pkg/utils"
)

func main() {
	// Optional: without it, the reads that go over WSMAN use the Local System Account.
	password := os.Getenv("AMT_PASSWORD")

	// The zero value reads what `rpc amtinfo` shows by default.
	result, err := amtinfo.Get(amtinfo.Options{AMTPassword: password})
	report("Get", result, err)

	// A selective read: only the selected fields are read.
	result, err = amtinfo.Get(amtinfo.Options{Version: true, ControlMode: true, UUID: true})
	report("Get version, control mode and UUID", result, err)

	// Sync to Console only when its devices API URL is given.
	if url := os.Getenv("CONSOLE_DEVICES_URL"); url != "" {
		result, err = amtinfo.Sync(amtinfo.SyncOptions{
			URL:           url,
			AMTPassword:   password,
			SkipCertCheck: os.Getenv("SKIP_CERT_CHECK") == "true",
			TenantID:      os.Getenv("TENANT_ID"),
			AuthToken:     os.Getenv("AUTH_TOKEN"),
			AuthUsername:  os.Getenv("AUTH_USERNAME"),
			AuthPassword:  os.Getenv("AUTH_PASSWORD"),
			AuthEndpoint:  os.Getenv("AUTH_ENDPOINT"),
		})
		report("Sync", result, err)
	}
}

// report prints result as indented JSON. With an IncorrectPermissions error the
// result still holds what could be read without elevated privileges; any
// other error ends the program.
func report(name string, result *amtinfo.Result, err error) {
	fmt.Printf("=== %s ===\n", name)

	switch {
	case errors.Is(err, utils.IncorrectPermissions):
		fmt.Fprintf(os.Stderr, "%s: run elevated (administrator or root) for full AMT data; showing what was read\n", name)
	case err != nil:
		fmt.Fprintf(os.Stderr, "%s failed: %v\n", name, err)
		os.Exit(1)
	case result.HECIAvailable != nil && !*result.HECIAvailable:
		fmt.Fprintf(os.Stderr, "%s: HECI not available; AMT may not be present on this device\n", name)
	}

	out, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s: %v\n", name, err)
		os.Exit(1)
	}

	fmt.Println(string(out))
}
