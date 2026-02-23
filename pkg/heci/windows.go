//go:build windows
// +build windows

/*********************************************************************
 * Copyright (c) Intel Corporation 2021
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/
package heci

import (
	"bytes"
	"encoding/binary"
	"errors"
	"reflect"
	"syscall"
	"unsafe"

	setupapi "github.com/device-management-toolkit/rpc-go/v2/pkg/windows"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sys/windows"
)

const (
	FILE_DEVICE_HECI = 0x8000
	METHOD_BUFFERED  = 0
)

func ctl_code(device_type, function, method, access uint32) uint32 {
	return (device_type << 16) | (access << 14) | (function << 2) | method
}

type Driver struct {
	meiDevice      windows.Handle
	bufferSize     uint32
	PTHIGUID       windows.GUID
	LMEGUID        windows.GUID
	WDGUID         windows.GUID
	clientGUID     *windows.GUID
	clientGUIDSize uint32
}

type HeciVersion struct {
	major  uint8
	minor  uint8
	hotfix uint8
	build  uint16
}
type HeciVersionPacked struct {
	packed [5]byte
}

func NewDriver() *Driver {
	return &Driver{}
}

func (heci *Driver) Init(useLME, useWD bool) error {
	var err, err2 error

	heci.LMEGUID, err = windows.GUIDFromString("{6733A4DB-0476-4E7B-B3AF-BCFC29BEE7A7}")
	if err != nil {
		return err
	}

	heci.PTHIGUID, err = windows.GUIDFromString("{12F80028-B4B7-4B2D-ACA8-46E0FF65814C}")
	if err != nil {
		return err
	}

	heci.WDGUID, err = windows.GUIDFromString("{05B79A6F-4628-4D7F-899D-A91514CB32AB}")
	if err != nil {
		return err
	}

	if useLME {
		heci.clientGUID = &heci.LMEGUID
	} else if useWD {
		heci.clientGUID = &heci.WDGUID
	} else {
		heci.clientGUID = &heci.PTHIGUID
	}

	err2 = heci.FindDevices()
	if err2 != nil {
		return err2
	}

	return err
}

func (heci *Driver) FindDevices() error {
	deviceGUID, err := windows.GUIDFromString("{E2D1FF34-3458-49A9-88DA-8E6915CE9BE5}")
	if err != nil {
		return err
	}

	deviceInfo, err := setupapi.SetupDiGetClassDevs(&deviceGUID, nil, 0, setupapi.DIGCF_PRESENT|setupapi.DIGCF_DEVICEINTERFACE)
	if err != nil {
		return err
	}

	if deviceInfo == syscall.InvalidHandle {
		return errors.New("invalid handle")
	}

	interfaceData := setupapi.SpDevInterfaceData{}
	interfaceData.CbSize = (uint32)(unsafe.Sizeof(interfaceData))

	edi, err := setupapi.SetupDiEnumDeviceInterfaces(deviceInfo, nil, &deviceGUID, 0, &interfaceData)
	if err != nil {
		// Clean up device info before returning
		setupapi.SetupDiDestroyDeviceInfoList(deviceInfo)
		// Check if this is a "no devices found" error (ERROR_NO_MORE_ITEMS = 259)
		if errno, ok := err.(syscall.Errno); ok && errno == syscall.Errno(259) {
			log.Error("MEI/HECI driver not found or no Intel ME devices present")
			return errors.New("MEI/HECI driver not found. Please ensure the Intel Management Engine Interface driver is installed")
		}
		log.Errorf("FindDevices: SetupDiEnumDeviceInterfaces failed: %v", err)
		return err
	}

	if edi == syscall.InvalidHandle {
		return errors.New("invalid handle")
	}

	err = setupapi.SetupDiGetDeviceInterfaceDetail(deviceInfo, &interfaceData, nil, 0, &heci.bufferSize, nil)
	if err != nil && heci.bufferSize == 0 {
		return err
	}

	buf := make([]uint16, heci.bufferSize)
	buf[0] = 8

	err = setupapi.SetupDiGetDeviceInterfaceDetail(deviceInfo, &interfaceData, &buf[0], heci.bufferSize, nil, nil)
	if err != nil {
		return err
	}

	const firstChar = 2

	l := firstChar
	for l < len(buf) && buf[l] != 0 {
		l++
	}

	err = setupapi.SetupDiDestroyDeviceInfoList(deviceInfo)
	if err != nil {
		return err
	}

	heci.meiDevice, err = windows.CreateFile(&buf[2], windows.GENERIC_READ|windows.GENERIC_WRITE, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_OVERLAPPED, 0)
	if err != nil {
		return err
	}

	err = heci.GetHeciVersion()
	if err != nil {
		heci.meiDevice = 0
		return err
	}

	err = heci.ConnectHeciClient()
	if err != nil {
		heci.meiDevice = 0
		return err
	}

	return nil
}

func (heci *Driver) GetBufferSize() uint32 {
	return heci.bufferSize
}

func (heci *Driver) GetHeciVersion() error {
	version := HeciVersion{}
	packedVersion := HeciVersionPacked{}
	versionSize := unsafe.Sizeof(packedVersion)

	err := heci.doIoctl(ctl_code(FILE_DEVICE_HECI, 0x800, METHOD_BUFFERED, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE), nil, 0, (*byte)(unsafe.Pointer(&packedVersion.packed)), (uint32)(versionSize))
	if err != nil {
		return err
	}

	buf2 := bytes.NewBuffer(packedVersion.packed[:])
	binary.Read(buf2, binary.LittleEndian, &version.major)
	binary.Read(buf2, binary.LittleEndian, &version.minor)
	binary.Read(buf2, binary.LittleEndian, &version.hotfix)
	binary.Read(buf2, binary.LittleEndian, &version.build)

	return nil
}

func (heci *Driver) ConnectHeciClient() error {
	properties := MEIConnectClientData{}
	propertiesPacked := CMEIConnectClientData{}
	propertiesSize := unsafe.Sizeof(propertiesPacked)
	guidSize := reflect.Indirect(reflect.ValueOf(heci.clientGUID)).Type().Size()

	err := heci.doIoctl(
		ctl_code(FILE_DEVICE_HECI, 0x801, METHOD_BUFFERED, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE),
		(*byte)(unsafe.Pointer(heci.clientGUID)),
		(uint32)(guidSize),
		(*byte)(unsafe.Pointer(&propertiesPacked.data)),
		(uint32)(propertiesSize),
	)
	if err != nil {
		log.Tracef("ConnectHeciClient: IOCTL failed: %v", err)
		return err
	}

	buf2 := bytes.NewBuffer(propertiesPacked.data[:])
	binary.Read(buf2, binary.LittleEndian, &properties)
	heci.bufferSize = properties.MaxMessageLength

	return nil
}

func (heci *Driver) doIoctl(controlCode uint32, inBuf *byte, intsize uint32, outBuf *byte, outsize uint32) (err error) {
	var bytesRead uint32

	var overlapped windows.Overlapped

	overlapped.HEvent, err = windows.CreateEvent(nil, 0, 0, nil)
	defer windows.CloseHandle(overlapped.HEvent)

	overlapped.Offset = 0
	overlapped.OffsetHigh = 0

	if err != nil {
		return errors.New("couldn't create some sort of event")
	}

	windows.DeviceIoControl(heci.meiDevice, controlCode, inBuf, intsize, outBuf, outsize, &bytesRead, &overlapped)

	windows.WaitForSingleObject(overlapped.HEvent, windows.INFINITE)

	err = windows.GetOverlappedResult(heci.meiDevice, &overlapped, &bytesRead, true)
	if err != nil {
		return err
	}

	return nil
}

func (heci *Driver) SendMessage(buffer []byte, done *uint32) (bytesWritten uint32, err error) {
	var overlapped windows.Overlapped

	overlapped.HEvent, err = windows.CreateEvent(nil, 0, 0, nil)
	defer windows.CloseHandle(overlapped.HEvent)

	overlapped.Offset = 0
	overlapped.OffsetHigh = 0

	if err != nil {
		return 0, errors.New("couldn't create some sort of event")
	}

	windows.WriteFile(heci.meiDevice, buffer, done, &overlapped)

	event, err := windows.WaitForSingleObject(overlapped.HEvent, 2000)
	if event == (uint32)(windows.WAIT_TIMEOUT) {
		return 0, errors.New("wait timeout while sending data")
	}

	err = windows.GetOverlappedResult(heci.meiDevice, &overlapped, done, false)
	if err != nil {
		return 0, err
	}

	return *done, nil
}

func (heci *Driver) ReceiveMessage(buffer []byte, done *uint32) (bytesRead uint32, err error) {
	var overlapped windows.Overlapped

	overlapped.HEvent, err = windows.CreateEvent(nil, 0, 0, nil)
	defer windows.CloseHandle(overlapped.HEvent)

	overlapped.Offset = 0
	overlapped.OffsetHigh = 0

	if err != nil {
		return 0, errors.New("couldn't create some sort of event")
	}

	windows.ReadFile(heci.meiDevice, buffer, done, &overlapped)

	event, err := windows.WaitForSingleObject(overlapped.HEvent, windows.INFINITE)
	if event == (uint32)(windows.WAIT_TIMEOUT) {
		return 0, errors.New("wait timeout while sending data")
	}

	err = windows.GetOverlappedResult(heci.meiDevice, &overlapped, done, true)
	if err != nil {
		return 0, err
	}

	return *done, nil
}

func (heci *Driver) Close() {
	// NOTE: We intentionally do NOT call CloseHandle here. On some versions of
	// the Intel MEI driver (e.g. rolled-back/older drivers), calling CloseHandle
	// on the MEI device file handle after ConnectHeciClient triggers a null-pointer
	// execute-AV in the driver's kernel close dispatch routine, crashing the process.
	// Since rpc is a short-lived CLI process, the OS will clean up all open handles
	// when the process exits, so not closing explicitly is safe and correct.
	heci.meiDevice = 0
	heci.bufferSize = 0
}
