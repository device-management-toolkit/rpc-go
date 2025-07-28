//go:build linux
// +build linux

/*********************************************************************
 * Copyright (c) Intel Corporation 2024
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/

package amt

import (
	"context"
	"net"
	"os"
	"strings"
	"time"
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

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	resolver := &net.Resolver{}

	addrs, err := resolver.LookupHost(ctx, hostname)
	if err != nil {
		return "", err
	}

	names, err := resolver.LookupAddr(ctx, addrs[0])
	if err != nil {
		return "", err
	}

	return strings.TrimSuffix(names[0], "."), nil
}
