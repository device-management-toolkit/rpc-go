//go:build windows
// +build windows

/*********************************************************************
 * Copyright (c) Intel Corporation 2024
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/

package amt

import (
	"net"
	"os"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

func (amt AMTCommand) GetOSDNSSuffix() (string, error) {
	lanResult, _ := amt.GetLANInterfaceSettings(false)

	var (
		primarySuffix = ""
		b             []byte
	)

	l := uint32(15000) // recommended initial size
	for {
		b = make([]byte, l)

		err := windows.GetAdaptersAddresses(syscall.AF_UNSPEC, windows.GAA_FLAG_INCLUDE_PREFIX, 0, (*windows.IpAdapterAddresses)(unsafe.Pointer(&b[0])), &l)
		if err == nil {
			if l == 0 {
				return primarySuffix, nil
			}

			break
		}

		if err.(syscall.Errno) != syscall.ERROR_BUFFER_OVERFLOW {
			return primarySuffix, os.NewSyscallError("getadaptersaddresses", err)
		}

		if l <= uint32(len(b)) {
			return primarySuffix, os.NewSyscallError("getadaptersaddresses", err)
		}
	}

	for aa := (*windows.IpAdapterAddresses)(unsafe.Pointer(&b[0])); aa != nil; aa = aa.Next {
		if aa.PhysicalAddressLength <= 0 {
			continue
		}

		var curMacAddr = make(net.HardwareAddr, aa.PhysicalAddressLength)
		copy(curMacAddr, aa.PhysicalAddress[:])

		if curMacAddr.String() == lanResult.MACAddress {
			primarySuffix = windows.UTF16PtrToString(aa.DnsSuffix)

			break
		}
	}

	return primarySuffix, nil
}
