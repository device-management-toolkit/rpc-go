/*********************************************************************
 * Copyright (c) Intel Corporation 2026
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/

package main

import (
	"fmt"
	"os"
	"strconv"

	"github.com/device-management-toolkit/rpc-go/v2/pkg/deactivate"
)

const usage = `usage: deactivate-example [local|remote|console]

The mode defaults to local. Inputs are read from environment variables:
  local    AMT_PASSWORD (ACM), PARTIAL_UNPROVISION=true (ACM), DEVICE_UUID;
           Console cleanup: AUTH_ENDPOINT, AUTH_TOKEN or AUTH_USERNAME and
           AUTH_PASSWORD, DEVICES_ENDPOINT, TENANT_ID
  remote   RPS_URL, AMT_PASSWORD, FORCE=true, TLS_TUNNEL=true, TENANT_ID
  console  CONSOLE_URL, AMT_PASSWORD, AUTH_TOKEN or AUTH_USERNAME and
           AUTH_PASSWORD, AUTH_ENDPOINT, DEVICES_ENDPOINT, DEVICE_UUID, TENANT_ID

Set SKIP_CERT_CHECK=true or SKIP_AMT_CERT_CHECK=true to skip TLS verification
of Console/RPS or of AMT. An empty AMT_PASSWORD is prompted for when needed.
`

func main() {
	mode := "local"

	switch len(os.Args) {
	case 1:
	case 2:
		mode = os.Args[1]
	default:
		exitUsage()
	}

	var err error

	switch mode {
	case "local":
		err = deactivate.Run(localOptions())
	case "remote":
		err = deactivate.Remote(remoteOptions())
	case "console":
		err = deactivate.Console(consoleOptions())
	default:
		exitUsage()
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "%s deactivation failed: %v\n", mode, err)
		os.Exit(1)
	}

	fmt.Println("Device deactivated successfully")
}

func exitUsage() {
	fmt.Fprint(os.Stderr, usage)
	os.Exit(2)
}

func localOptions() deactivate.Options {
	return deactivate.Options{
		AMTPassword:        os.Getenv("AMT_PASSWORD"),
		PartialUnprovision: envBool("PARTIAL_UNPROVISION"),
		SkipAMTCertCheck:   envBool("SKIP_AMT_CERT_CHECK"),
		UUID:               os.Getenv("DEVICE_UUID"),
		SkipCertCheck:      envBool("SKIP_CERT_CHECK"),
		TenantID:           os.Getenv("TENANT_ID"),
		AuthToken:          os.Getenv("AUTH_TOKEN"),
		AuthUsername:       os.Getenv("AUTH_USERNAME"),
		AuthPassword:       os.Getenv("AUTH_PASSWORD"),
		AuthEndpoint:       os.Getenv("AUTH_ENDPOINT"),
		DevicesEndpoint:    os.Getenv("DEVICES_ENDPOINT"),
	}
}

func remoteOptions() deactivate.RemoteOptions {
	return deactivate.RemoteOptions{
		URL:              os.Getenv("RPS_URL"),
		AMTPassword:      os.Getenv("AMT_PASSWORD"),
		Force:            envBool("FORCE"),
		TLSTunnel:        envBool("TLS_TUNNEL"),
		TenantID:         os.Getenv("TENANT_ID"),
		SkipCertCheck:    envBool("SKIP_CERT_CHECK"),
		SkipAMTCertCheck: envBool("SKIP_AMT_CERT_CHECK"),
	}
}

func consoleOptions() deactivate.ConsoleOptions {
	return deactivate.ConsoleOptions{
		URL:              os.Getenv("CONSOLE_URL"),
		AMTPassword:      os.Getenv("AMT_PASSWORD"),
		UUID:             os.Getenv("DEVICE_UUID"),
		SkipAMTCertCheck: envBool("SKIP_AMT_CERT_CHECK"),
		SkipCertCheck:    envBool("SKIP_CERT_CHECK"),
		TenantID:         os.Getenv("TENANT_ID"),
		AuthToken:        os.Getenv("AUTH_TOKEN"),
		AuthUsername:     os.Getenv("AUTH_USERNAME"),
		AuthPassword:     os.Getenv("AUTH_PASSWORD"),
		AuthEndpoint:     os.Getenv("AUTH_ENDPOINT"),
		DevicesEndpoint:  os.Getenv("DEVICES_ENDPOINT"),
	}
}

// envBool reports whether the environment variable holds a true value such as "true" or "1".
func envBool(name string) bool {
	value, _ := strconv.ParseBool(os.Getenv(name))

	return value
}
