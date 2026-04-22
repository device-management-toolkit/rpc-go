//go:build windows

/*********************************************************************
 * Copyright (c) Intel Corporation 2021
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/
package heci

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"reflect"
	"syscall"
	"unsafe"

	"github.com/device-management-toolkit/rpc-go/v2/pkg/utils"
	setupapi "github.com/device-management-toolkit/rpc-go/v2/pkg/windows"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sys/windows"
)

// isOverlappedPending reports whether err is the expected "I/O started, wait for the event" signal.
// WriteFile/ReadFile/DeviceIoControl on an overlapped handle return this when the operation was
// accepted and will complete asynchronously; treat anything else as a real failure.
func isOverlappedPending(err error) bool {
	return err == nil || errors.Is(err, windows.ERROR_IO_PENDING)
}

const (
	FILE_DEVICE_HECI = 0x8000
	METHOD_BUFFERED  = 0
)

func ctl_code(device_type, function, method, access uint32) uint32 {
	return (device_type << 16) | (access << 14) | (function << 2) | method
}

type Driver struct {
	meiDevice       windows.Handle
	bufferSize      uint32
	protocolVersion uint8
	PTHIGUID        windows.GUID
	LMEGUID         windows.GUID
	WDGUID          windows.GUID
	UPIDGUID        windows.GUID
	HOTHAMGUID      windows.GUID
	clientGUID      *windows.GUID
	clientGUIDSize  uint32
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

	heci.UPIDGUID, err = windows.GUIDFromString("{92136C79-5FEA-4CFD-980E-23BE07FA5E9F}")
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

// InitWithGUID initializes the HECI driver with a specific GUID
func (heci *Driver) InitWithGUID(guid interface{}) error {
	// Type assert to windows.GUID
	guidValue, ok := guid.(windows.GUID)
	if !ok {
		return errors.New("invalid GUID type for Windows, expected windows.GUID")
	}

	heci.clientGUID = &guidValue

	err := heci.FindDevices()
	if err != nil {
		return err
	}

	return nil
}

func (heci *Driver) InitHOTHAM() error {
	var err error

	// HOTHAM GUID
	heci.HOTHAMGUID, err = windows.GUIDFromString("{082EE5A7-7C25-470A-9643-0C06F0466EA1}")
	if err != nil {
		log.Errorf("InitHOTHAM: Failed to parse HOTHAM GUID: %v", err)
		return err
	}

	heci.clientGUID = &heci.HOTHAMGUID

	err = heci.FindDevices()
	if err != nil {
		log.Errorf("InitHOTHAM: Failed to find devices: %v", err)
		return err
	}

	log.Tracef("InitHOTHAM: Connected to HOTHAM GUID: %s, Buffer size: %d, Protocol version: %d",
		heci.HOTHAMGUID.String(), heci.bufferSize, heci.protocolVersion)

	return nil
}

func (heci *Driver) FindDevices() error {
	deviceGUID, err := windows.GUIDFromString("{E2D1FF34-3458-49A9-88DA-8E6915CE9BE5}")
	if err != nil {
		log.Errorf("FindDevices: Failed to parse device GUID: %v", err)
		return err
	}

	deviceInfo, err := setupapi.SetupDiGetClassDevs(&deviceGUID, nil, 0, setupapi.DIGCF_PRESENT|setupapi.DIGCF_DEVICEINTERFACE)
	if err != nil {
		log.Errorf("FindDevices: SetupDiGetClassDevs failed: %v", err)
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
	heci.protocolVersion = properties.ProtocolVersion

	return nil
}

func (heci *Driver) doIoctl(controlCode uint32, inBuf *byte, intsize uint32, outBuf *byte, outsize uint32) (err error) {
	var bytesRead uint32

	var overlapped windows.Overlapped

	overlapped.HEvent, err = windows.CreateEvent(nil, 0, 0, nil)
	if err != nil {
		return fmt.Errorf("CreateEvent failed: %w", err)
	}

	defer windows.CloseHandle(overlapped.HEvent)

	overlapped.Offset = 0
	overlapped.OffsetHigh = 0

	// DeviceIoControl may complete synchronously (err == nil) or signal ERROR_IO_PENDING.
	// Any other error means the kernel rejected the request and the event will never fire,
	// so bail out before we wait on it.
	if ioctlErr := windows.DeviceIoControl(heci.meiDevice, controlCode, inBuf, intsize, outBuf, outsize, &bytesRead, &overlapped); !isOverlappedPending(ioctlErr) {
		return fmt.Errorf("DeviceIoControl failed: %w", ioctlErr)
	}

	// Bounded wait mirrors SendMessage/ReceiveMessage so a stuck IOCTL surfaces as an error
	// rather than hanging the init path forever.
	timeoutMs := uint32(utils.HeciReadTimeout * 1000)

	event, waitErr := windows.WaitForSingleObject(overlapped.HEvent, timeoutMs)
	switch {
	case event == uint32(windows.WAIT_TIMEOUT):
		_ = windows.CancelIoEx(heci.meiDevice, &overlapped)

		return errors.New("wait timeout during IOCTL")
	case event == uint32(windows.WAIT_FAILED) || waitErr != nil:
		_ = windows.CancelIoEx(heci.meiDevice, &overlapped)

		if waitErr == nil {
			waitErr = errors.New("wait failed during IOCTL")
		}

		return waitErr
	}

	err = windows.GetOverlappedResult(heci.meiDevice, &overlapped, &bytesRead, true)
	if err != nil {
		return err
	}

	return nil
}

func (heci *Driver) SendMessage(buffer []byte, done *uint32) (bytesWritten int, err error) {
	var overlapped windows.Overlapped

	overlapped.HEvent, err = windows.CreateEvent(nil, 0, 0, nil)
	if err != nil {
		return 0, fmt.Errorf("CreateEvent failed: %w", err)
	}

	defer windows.CloseHandle(overlapped.HEvent)

	overlapped.Offset = 0
	overlapped.OffsetHigh = 0

	// WriteFile on an overlapped handle returns nil (sync completion) or ERROR_IO_PENDING.
	// Other errors mean the driver rejected the write and no event will ever fire.
	if writeErr := windows.WriteFile(heci.meiDevice, buffer, done, &overlapped); !isOverlappedPending(writeErr) {
		return 0, fmt.Errorf("WriteFile failed: %w", writeErr)
	}

	event, werr := windows.WaitForSingleObject(overlapped.HEvent, 2000)
	switch {
	case event == uint32(windows.WAIT_TIMEOUT):
		_ = windows.CancelIoEx(heci.meiDevice, &overlapped)

		return 0, errors.New("wait timeout while sending data")
	case event == uint32(windows.WAIT_FAILED) || werr != nil:
		_ = windows.CancelIoEx(heci.meiDevice, &overlapped)

		if werr == nil {
			werr = errors.New("wait failed while sending data")
		}

		return 0, werr
	}

	// bWait=true so GOR doesn't race the auto-reset event and return ERROR_IO_INCOMPLETE
	// ("Overlapped I/O event is not in a signaled state") on completed operations.
	err = windows.GetOverlappedResult(heci.meiDevice, &overlapped, done, true)
	if err != nil {
		return 0, err
	}

	return int(*done), nil
}

func (heci *Driver) ReceiveMessage(buffer []byte, done *uint32) (bytesRead int, err error) {
	var overlapped windows.Overlapped

	overlapped.HEvent, err = windows.CreateEvent(nil, 0, 0, nil)
	if err != nil {
		return 0, fmt.Errorf("CreateEvent failed: %w", err)
	}

	defer windows.CloseHandle(overlapped.HEvent)

	overlapped.Offset = 0
	overlapped.OffsetHigh = 0

	// ReadFile on an overlapped handle returns nil (sync completion) or ERROR_IO_PENDING.
	// Other errors mean the driver rejected the read and no event will ever fire.
	if readErr := windows.ReadFile(heci.meiDevice, buffer, done, &overlapped); !isOverlappedPending(readErr) {
		return 0, fmt.Errorf("ReadFile failed: %w", readErr)
	}

	// Bounded wait so callers see ErrReadTimeout instead of blocking forever (parity with Linux).
	timeoutMs := uint32(utils.HeciReadTimeout * 1000)

	event, err := windows.WaitForSingleObject(overlapped.HEvent, timeoutMs)
	switch {
	case event == uint32(windows.WAIT_TIMEOUT):
		// Cancel the dangling ReadFile so it doesn't write into a reused buffer after return.
		_ = windows.CancelIoEx(heci.meiDevice, &overlapped)

		return 0, ErrReadTimeout
	case event == uint32(windows.WAIT_FAILED) || err != nil:
		// WaitForSingleObject itself failed; cancel the pending IO before returning so it
		// can't scribble into a buffer the caller is about to reuse.
		_ = windows.CancelIoEx(heci.meiDevice, &overlapped)

		if err == nil {
			err = errors.New("wait failed while receiving data")
		}

		return 0, err
	}

	err = windows.GetOverlappedResult(heci.meiDevice, &overlapped, done, true)
	if err != nil {
		return 0, err
	}

	return int(*done), nil
}

func (heci *Driver) Close() {
	// Release the MEI handle; leaking across Open/Close cycles starves the driver. (Requires current MEI driver.)
	if heci.meiDevice != 0 && heci.meiDevice != windows.InvalidHandle {
		if err := windows.CloseHandle(heci.meiDevice); err != nil {
			log.Debugf("MEI CloseHandle returned: %v", err)
		}
	}

	heci.meiDevice = 0
	heci.bufferSize = 0
}
