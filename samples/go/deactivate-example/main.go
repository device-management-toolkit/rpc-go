/*********************************************************************
 * Copyright (c) Intel Corporation 2026
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/

package main

import (
	"fmt"
	"os"

	"github.com/device-management-toolkit/rpc-go/v2/pkg/deactivate"
)

func main() {
	opts := deactivate.Options{
		AMTPassword: os.Getenv("AMT_PASSWORD"),
	}

	if err := deactivate.Run(opts); err != nil {
		fmt.Fprintf(os.Stderr, "deactivation failed: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("Device deactivated successfully")
}
