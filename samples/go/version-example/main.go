/*********************************************************************
 * Copyright (c) Intel Corporation 2025
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/

package main

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/device-management-toolkit/rpc-go/v2/pkg/version"
)

func main() {
	info := version.Get()

	out, err := json.MarshalIndent(info, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	fmt.Println(string(out))
}
