/*********************************************************************
 * Copyright (c) Intel Corporation 2026
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/

package main

import (
	"fmt"
	"os"
	"strconv"

	"github.com/device-management-toolkit/rpc-go/v2/pkg/activate"
)

const usage = `usage: activate-example ccm|acm|stop|remote|profile

Inputs are read from environment variables:
  ccm      AMT_PASSWORD
  acm      AMT_PASSWORD, PROVISIONING_CERT, PROVISIONING_CERT_PASSWORD, MEBX_PASSWORD
  stop     (none)
  remote   RPS_URL, RPS_PROFILE, AMT_PASSWORD (activated devices), TENANT_ID,
           RPS_PROXY, TLS_TUNNEL=true (AMT 11-18), DNS_SUFFIX, HOSTNAME_OVERRIDE,
           DEVICE_UUID, FRIENDLY_NAME
  profile  PROFILE_PATH or PROFILE_URL, RPC_EXECUTABLE, CONFIG_ENCRYPTION_KEY,
           AMT_PASSWORD, MEBX_PASSWORD

Console registration (ccm, acm, profile): AUTH_ENDPOINT, AUTH_TOKEN or
AUTH_USERNAME and AUTH_PASSWORD, DEVICES_ENDPOINT, TENANT_ID.
Set SKIP_CERT_CHECK=true or SKIP_AMT_CERT_CHECK=true to skip TLS verification
of Console/RPS or of AMT. An empty AMT_PASSWORD or MEBX_PASSWORD is prompted for.
`

func main() {
	mode := ""
	if len(os.Args) == 2 {
		mode = os.Args[1]
	}

	var err error

	switch mode {
	case "ccm":
		err = activate.Local(localOptions(activate.ModeCCM))
	case "acm":
		err = activate.Local(localOptions(activate.ModeACM))
	case "stop":
		err = activate.StopConfiguration(activate.StopConfigurationOptions{})
	case "remote":
		err = activate.Remote(remoteOptions())
	case "profile":
		err = activate.Profile(profileOptions())
	default:
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "%s failed: %v\n", mode, err)
		os.Exit(1)
	}

	fmt.Printf("%s completed successfully\n", mode)
}

func localOptions(mode activate.Mode) activate.LocalOptions {
	return activate.LocalOptions{
		Mode:                     mode,
		AMTPassword:              os.Getenv("AMT_PASSWORD"),
		ProvisioningCert:         os.Getenv("PROVISIONING_CERT"),
		ProvisioningCertPassword: os.Getenv("PROVISIONING_CERT_PASSWORD"),
		MEBxPassword:             os.Getenv("MEBX_PASSWORD"),
		SkipAMTCertCheck:         envBool("SKIP_AMT_CERT_CHECK"),
		SkipCertCheck:            envBool("SKIP_CERT_CHECK"),
		TenantID:                 os.Getenv("TENANT_ID"),
		AuthToken:                os.Getenv("AUTH_TOKEN"),
		AuthUsername:             os.Getenv("AUTH_USERNAME"),
		AuthPassword:             os.Getenv("AUTH_PASSWORD"),
		AuthEndpoint:             os.Getenv("AUTH_ENDPOINT"),
		DevicesEndpoint:          os.Getenv("DEVICES_ENDPOINT"),
	}
}

func remoteOptions() activate.RemoteOptions {
	return activate.RemoteOptions{
		URL:              os.Getenv("RPS_URL"),
		Profile:          os.Getenv("RPS_PROFILE"),
		AMTPassword:      os.Getenv("AMT_PASSWORD"),
		DNSSuffix:        os.Getenv("DNS_SUFFIX"),
		Hostname:         os.Getenv("HOSTNAME_OVERRIDE"),
		UUID:             os.Getenv("DEVICE_UUID"),
		FriendlyName:     os.Getenv("FRIENDLY_NAME"),
		Proxy:            os.Getenv("RPS_PROXY"),
		TLSTunnel:        envBool("TLS_TUNNEL"),
		TenantID:         os.Getenv("TENANT_ID"),
		SkipCertCheck:    envBool("SKIP_CERT_CHECK"),
		SkipAMTCertCheck: envBool("SKIP_AMT_CERT_CHECK"),
	}
}

func profileOptions() activate.ProfileOptions {
	return activate.ProfileOptions{
		File:             os.Getenv("PROFILE_PATH"),
		URL:              os.Getenv("PROFILE_URL"),
		Key:              os.Getenv("CONFIG_ENCRYPTION_KEY"),
		Executable:       os.Getenv("RPC_EXECUTABLE"),
		AMTPassword:      os.Getenv("AMT_PASSWORD"),
		MEBxPassword:     os.Getenv("MEBX_PASSWORD"),
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
