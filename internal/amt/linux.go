//go:build linux
// +build linux

/*********************************************************************
 * Copyright (c) Intel Corporation 2024
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/

package amt

import (
	"net"
	"os"
	"strings"
)

func (amt AMTCommand) GetOSDNSSuffix() (string, error) {
	fqdn, err := getFQDN()
	if err != nil {
		return "", err
	}

	splitName := strings.SplitAfterN(fqdn, ".", 2)
	if len(splitName) == 2 {
		return splitName[1], nil
	}

	return fqdn, err
}

func getFQDN() (string, error) {
	hostname, err := os.Hostname()
	if err != nil {
		return "", err
	}

	if strings.Contains(hostname, ".") {
		return hostname, nil
	}

	addrs, err := net.LookupHost(hostname)
	if err != nil {
		return "", err
	}

	names, err := net.LookupAddr(addrs[0])
	if err != nil {
		return "", err
	}

	return strings.TrimSuffix(names[0], "."), nil
}
