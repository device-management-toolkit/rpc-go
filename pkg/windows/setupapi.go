//go:build windows
// +build windows

/*********************************************************************
 * Copyright (c) Intel Corporation 2021
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/
package windows

import (
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

type SpDevinfoData struct {
	CbSize    uint32
	ClassGuid windows.GUID
	DevInst   uint32
	Reserved  uintptr
}
type SpDevInterfaceData struct {
	CbSize             uint32
	InterfaceClassGuid windows.GUID
	Flags              uint32
	Reserved           uintptr
}
type SpDevInterfaceDetailData struct {
	CbSize     uint32
	DevicePath [256]uint16
}

const (
	SpDevinfoDataSz = 0x20

	DIGCF_PRESENT         = 0x2
	DIGCF_DEVICEINTERFACE = 0x10
)

var (
	modsetupapi = syscall.NewLazyDLL("setupapi.dll")

	procSetupDiGetClassDevsW              = modsetupapi.NewProc("SetupDiGetClassDevsW")
	procSetupDiGetDeviceRegistryPropertyW = modsetupapi.NewProc("SetupDiGetDeviceRegistryPropertyW")
	procSetupDiEnumDeviceInfo             = modsetupapi.NewProc("SetupDiEnumDeviceInfo")
	procSetupDiCreateDeviceInfoW          = modsetupapi.NewProc("SetupDiCreateDeviceInfoW")
	procSetupDiCreateDeviceInfoList       = modsetupapi.NewProc("SetupDiCreateDeviceInfoList")
	procSetupDiSetDeviceRegistryPropertyW = modsetupapi.NewProc("SetupDiSetDeviceRegistryPropertyW")
	procSetupDiCallClassInstaller         = modsetupapi.NewProc("SetupDiCallClassInstaller")
	procSetupDiDestroyDeviceInfoList      = modsetupapi.NewProc("SetupDiDestroyDeviceInfoList")
	procSetupDiGetINFClassW               = modsetupapi.NewProc("SetupDiGetINFClassW")
	procSetupDiOpenDevRegKey              = modsetupapi.NewProc("SetupDiOpenDevRegKey")
	procSetupDiGetDeviceInstanceIdW       = modsetupapi.NewProc("SetupDiGetDeviceInstanceIdW")
	procSetupDiEnumDeviceInterfaces       = modsetupapi.NewProc("SetupDiEnumDeviceInterfaces")
	procSetupDiGetDeviceInterfaceDetailW  = modsetupapi.NewProc("SetupDiGetDeviceInterfaceDetailW")
)

func SetupDiGetClassDevs(class *windows.GUID, enum *uint16, parent syscall.Handle, flags uint32) (devInfoSet syscall.Handle, err error) {
	r0, _, e1 := syscall.SyscallN(procSetupDiGetClassDevsW.Addr(), uintptr(unsafe.Pointer(class)), uintptr(unsafe.Pointer(enum)), uintptr(parent), uintptr(flags))
	devInfoSet = syscall.Handle(r0)

	if devInfoSet == syscall.InvalidHandle {
		if e1 != 0 {
			err = error(e1)
		} else {
			err = syscall.EINVAL
		}
	}

	return devInfoSet, err
}

func SetupDiGetDeviceRegistryProperty(devInfoSet syscall.Handle, diData *SpDevinfoData, prop uint32, regDataType *uint32, buf []byte, size *uint32) (err error) {
	var _p0 *byte
	if len(buf) > 0 {
		_p0 = &buf[0]
	}

	r1, _, e1 := syscall.SyscallN(procSetupDiGetDeviceRegistryPropertyW.Addr(), uintptr(devInfoSet), uintptr(unsafe.Pointer(diData)), uintptr(prop), uintptr(unsafe.Pointer(regDataType)), uintptr(unsafe.Pointer(_p0)), uintptr(len(buf)), uintptr(unsafe.Pointer(size)))
	if r1 == 0 {
		if e1 != 0 {
			err = error(e1)
		} else {
			err = syscall.EINVAL
		}
	}

	return err
}

func SetupDiEnumDeviceInfo(devInfoSet syscall.Handle, index uint32, diData *SpDevinfoData) (err error) {
	r1, _, e1 := syscall.SyscallN(procSetupDiEnumDeviceInfo.Addr(), uintptr(devInfoSet), uintptr(index), uintptr(unsafe.Pointer(diData)))
	if r1 == 0 {
		if e1 != 0 {
			err = error(e1)
		} else {
			err = syscall.EINVAL
		}
	}

	return err
}

func SetupDiCreateDeviceInfo(devInfoSet syscall.Handle, devName *uint16, g *windows.GUID, devDesc *uint16, hwnd uintptr, cflags uint32, dataOut *SpDevinfoData) (err error) {
	r1, _, e1 := syscall.SyscallN(procSetupDiCreateDeviceInfoW.Addr(), uintptr(devInfoSet), uintptr(unsafe.Pointer(devName)), uintptr(unsafe.Pointer(g)), uintptr(unsafe.Pointer(devDesc)), hwnd, uintptr(cflags), uintptr(unsafe.Pointer(dataOut)))
	if r1 == 0 {
		if e1 != 0 {
			err = error(e1)
		} else {
			err = syscall.EINVAL
		}
	}

	return err
}

func SetupDiCreateDeviceInfoList(g *windows.GUID, hwnd uintptr) (devInfoSet syscall.Handle, err error) {
	r0, _, e1 := syscall.SyscallN(procSetupDiCreateDeviceInfoList.Addr(), uintptr(unsafe.Pointer(g)), hwnd)
	devInfoSet = syscall.Handle(r0)

	if devInfoSet == syscall.InvalidHandle {
		if e1 != 0 {
			err = error(e1)
		} else {
			err = syscall.EINVAL
		}
	}

	return devInfoSet, err
}

func SetupDiSetDeviceRegistryProperty(devInfoSet syscall.Handle, data *SpDevinfoData, prop uint32, buf *byte, sz uint32) (err error) {
	r1, _, e1 := syscall.SyscallN(procSetupDiSetDeviceRegistryPropertyW.Addr(), uintptr(devInfoSet), uintptr(unsafe.Pointer(data)), uintptr(prop), uintptr(unsafe.Pointer(buf)), uintptr(sz))
	if r1 == 0 {
		if e1 != 0 {
			err = error(e1)
		} else {
			err = syscall.EINVAL
		}
	}

	return err
}

func SetupDiCallClassInstaller(installFn uintptr, devInfoSet syscall.Handle, data *SpDevinfoData) (err error) {
	r1, _, e1 := syscall.SyscallN(procSetupDiCallClassInstaller.Addr(), installFn, uintptr(devInfoSet), uintptr(unsafe.Pointer(data)))
	if r1 == 0 {
		if e1 != 0 {
			err = error(e1)
		} else {
			err = syscall.EINVAL
		}
	}

	return err
}

func SetupDiDestroyDeviceInfoList(devInfoSet syscall.Handle) (err error) {
	r1, _, e1 := syscall.SyscallN(procSetupDiDestroyDeviceInfoList.Addr(), uintptr(devInfoSet))
	if r1 == 0 {
		if e1 != 0 {
			err = error(e1)
		} else {
			err = syscall.EINVAL
		}
	}

	return err
}

func SetupDiGetINFClass(infPath *uint16, guid *windows.GUID, className []uint16, reqSz *uint32) (err error) {
	var _p0 *uint16
	if len(className) > 0 {
		_p0 = &className[0]
	}

	r1, _, e1 := syscall.SyscallN(procSetupDiGetINFClassW.Addr(), uintptr(unsafe.Pointer(infPath)), uintptr(unsafe.Pointer(guid)), uintptr(unsafe.Pointer(_p0)), uintptr(len(className)), uintptr(unsafe.Pointer(reqSz)))
	if r1 == 0 {
		if e1 != 0 {
			err = error(e1)
		} else {
			err = syscall.EINVAL
		}
	}

	return err
}

func SetupDiOpenDevRegKey(devInfoSet syscall.Handle, diData *SpDevinfoData, scope, hwProfile, keyType, desiredAccess uint32) (h syscall.Handle, err error) {
	r0, _, e1 := syscall.SyscallN(procSetupDiOpenDevRegKey.Addr(), uintptr(devInfoSet), uintptr(unsafe.Pointer(diData)), uintptr(scope), uintptr(hwProfile), uintptr(keyType), uintptr(desiredAccess))
	h = syscall.Handle(r0)

	if h == syscall.InvalidHandle {
		if e1 != 0 {
			err = error(e1)
		} else {
			err = syscall.EINVAL
		}
	}

	return h, err
}

func SetupDiGetDeviceInstanceId(devInfoSet syscall.Handle, diData *SpDevinfoData, id []uint16, reqSz *uint32) (err error) {
	var _p0 *uint16
	if len(id) > 0 {
		_p0 = &id[0]
	}

	r1, _, e1 := syscall.SyscallN(procSetupDiGetDeviceInstanceIdW.Addr(), uintptr(devInfoSet), uintptr(unsafe.Pointer(diData)), uintptr(unsafe.Pointer(_p0)), uintptr(len(id)), uintptr(unsafe.Pointer(reqSz)))
	if r1 == 0 {
		if e1 != 0 {
			err = error(e1)
		} else {
			err = syscall.EINVAL
		}
	}

	return err
}

func SetupDiEnumDeviceInterfaces(devInfoSet syscall.Handle, deviceInfoData *SpDevinfoData, class *windows.GUID, memberIndex uint32, deviceInterfaceData *SpDevInterfaceData) (idk syscall.Handle, err error) {
	r0, _, e1 := syscall.SyscallN(procSetupDiEnumDeviceInterfaces.Addr(), uintptr(devInfoSet), uintptr(unsafe.Pointer(deviceInfoData)), uintptr(unsafe.Pointer(class)), uintptr(memberIndex), uintptr(unsafe.Pointer(deviceInterfaceData)))
	devInfoSet = syscall.Handle(r0)

	if devInfoSet == syscall.InvalidHandle {
		if e1 != 0 {
			err = error(e1)
		} else {
			err = syscall.EINVAL
		}
	}

	return idk, err
}

func SetupDiGetDeviceInterfaceDetail(devInfoSet syscall.Handle, dintfdata *SpDevInterfaceData, detail *uint16, detailSize uint32, reqsize *uint32, devInfData *SpDevinfoData) (err error) {
	r1, _, e1 := syscall.SyscallN(procSetupDiGetDeviceInterfaceDetailW.Addr(), uintptr(devInfoSet), uintptr(unsafe.Pointer(dintfdata)), uintptr(unsafe.Pointer(detail)), uintptr(detailSize), uintptr(unsafe.Pointer(reqsize)), uintptr(unsafe.Pointer(devInfData)))

	if r1 == 0 {
		if e1 != 0 {
			err = error(e1)
		} else {
			err = syscall.EINVAL
		}
	}

	return err
}
