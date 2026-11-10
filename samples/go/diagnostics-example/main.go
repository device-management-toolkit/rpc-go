/*********************************************************************
 * Copyright (c) Intel Corporation 2026
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/

package main

import (
	"errors"
	"fmt"
	"os"
	"strconv"

	"github.com/device-management-toolkit/rpc-go/v2/pkg/diagnostics"
)

const usage = `usage: diagnostics-example cira
       diagnostics-example csme <out-file>
       diagnostics-example wsman-list
       diagnostics-example wsman [class...]
       diagnostics-example bundle <out-zip>

wsman reads every class when none is named. Inputs are read from environment
variables: AMT_PASSWORD (wsman, bundle; if empty, the AMT Local System Account
is used), WSMAN_FORMAT (wsman: json, xml or table; default json) and
SKIP_AMT_CERT_CHECK=true to skip TLS verification of AMT.
`

func main() {
	if len(os.Args) < 2 {
		fail()
	}

	mode, args := os.Args[1], os.Args[2:]

	var err error

	switch {
	case mode == "cira" && len(args) == 0:
		err = runCIRA()
	case mode == "csme" && len(args) == 1:
		err = runCSME(args[0])
	case mode == "wsman-list" && len(args) == 0:
		for _, class := range diagnostics.WSMANClasses(diagnostics.WSMANClassesOptions{}) {
			fmt.Println(class)
		}
	case mode == "wsman":
		err = runWSMAN(args)
	case mode == "bundle" && len(args) == 1:
		err = runBundle(args[0])
	default:
		fail()
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "%s failed: %v\n", mode, err)
		os.Exit(1)
	}

	fmt.Fprintf(os.Stderr, "%s completed successfully\n", mode)
}

func fail() {
	fmt.Fprint(os.Stderr, usage)
	os.Exit(2)
}

func runCIRA() error {
	result, err := diagnostics.CIRA(diagnostics.CIRAOptions{})
	if err != nil {
		return err
	}

	fmt.Printf("CIRA tunnel opened: %t\n\n", result.Log.CiraStatusSummary.IsTunnelOpened == 1)
	fmt.Print(result.Text)

	return nil
}

func runCSME(output string) error {
	flashLog, err := diagnostics.CSME(diagnostics.CSMEOptions{})
	if err != nil {
		return err
	}

	if err := os.WriteFile(output, flashLog, 0o600); err != nil {
		return err
	}

	fmt.Printf("wrote %d bytes of CSME flash log to %s\n", len(flashLog), output)

	return nil
}

func runWSMAN(classes []string) error {
	result, err := diagnostics.WSMAN(diagnostics.WSMANOptions{
		Classes:          classes,
		All:              len(classes) == 0,
		Format:           os.Getenv("WSMAN_FORMAT"),
		AMTPassword:      os.Getenv("AMT_PASSWORD"),
		SkipAMTCertCheck: envBool("SKIP_AMT_CERT_CHECK"),
	})
	if result == nil {
		return err
	}

	fmt.Println(string(result.Output))

	for _, class := range result.Classes {
		if class.Err != nil {
			fmt.Fprintf(os.Stderr, "%s: %v\n", class.Class, class.Err)
		}
	}

	if errors.Is(err, diagnostics.ErrClassFetchFailed) {
		fmt.Fprintln(os.Stderr, "some classes could not be read")
	}

	return err
}

func runBundle(output string) error {
	result, err := diagnostics.Bundle(diagnostics.BundleOptions{
		Output:           output,
		AMTPassword:      os.Getenv("AMT_PASSWORD"),
		SkipAMTCertCheck: envBool("SKIP_AMT_CERT_CHECK"),
	})
	if result == nil {
		return err
	}

	fmt.Printf("bundle written to %s\n", result.Path)

	for _, collector := range result.Manifest.Collectors {
		fmt.Printf("  %-6s %-8s %s %s\n", collector.Name, collector.Status, collector.File, collector.Error)
	}

	if errors.Is(err, diagnostics.ErrBundleIncomplete) {
		fmt.Fprintln(os.Stderr, "the bundle is incomplete; see the manifest above")
	}

	return err
}

// envBool reports whether the environment variable holds a true value such as "true" or "1".
func envBool(name string) bool {
	value, _ := strconv.ParseBool(os.Getenv(name))

	return value
}
