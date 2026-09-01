//go:build !windows

/*********************************************************************
 * Copyright (c) Intel Corporation 2024
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/

package amt

import (
	"context"
	"net"
	"os"
	"os/exec"
	"strings"
	"time"
)

func (amt AMTCommand) GetOSDNSSuffix() (string, error) {
	fqdn, err := getFQDN()
	if err == nil {
		if suffix := dnsSuffixFromFQDN(fqdn); suffix != "" {
			return suffix, nil
		}
	}

	if suffix := getNetworkManagerDNSSuffix(); suffix != "" {
		return suffix, nil
	}

	return "", err
}

func dnsSuffixFromFQDN(fqdn string) string {
	_, suffix, found := strings.Cut(strings.TrimSuffix(strings.TrimSpace(fqdn), "."), ".")
	if !found {
		return ""
	}

	return suffix
}

func getNetworkManagerDNSSuffix() string {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	out, err := exec.CommandContext(ctx, "nmcli", "-g", "IP4.DOMAIN,IP4.SEARCHES", "device", "show").Output()
	if err != nil {
		return ""
	}

	for line := range strings.Lines(string(out)) {
		suffix := strings.TrimSpace(line)
		if suffix != "" && suffix != "--" {
			return suffix
		}
	}

	return ""
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
