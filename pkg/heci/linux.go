//go:build linux
// +build linux

/*********************************************************************
 * Copyright (c) Intel Corporation 2021
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/
package heci

import (
	"bytes"
	"encoding/binary"
	"os"
	"syscall"
	"unsafe"

	log "github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"
)

type Driver struct {
	meiDevice       *os.File
	bufferSize      uint32
	protocolVersion uint8
}

const (
	Device                   = "/dev/mei0"
	IOCTL_MEI_CONNECT_CLIENT = 0xC0104801
)

// PTHI
var MEI_IAMTHIF = [16]uint8{0x28, 0x00, 0xf8, 0x12, 0xb7, 0xb4, 0x2d, 0x4b, 0xac, 0xa8, 0x46, 0xe0, 0xff, 0x65, 0x81, 0x4c}

// LME
var MEI_LMEIF = [16]uint8{0xdb, 0xa4, 0x33, 0x67, 0x76, 0x04, 0x7b, 0x4e, 0xb3, 0xaf, 0xbc, 0xfc, 0x29, 0xbe, 0xe7, 0xa7}

// Watchdog (WD)
var MEI_WDIF = [16]uint8{0x6f, 0x9a, 0xb7, 0x05, 0x28, 0x46, 0x7f, 0x4d, 0x89, 0x9D, 0xA9, 0x15, 0x14, 0xCB, 0x32, 0xAB}

func NewDriver() *Driver {
	return &Driver{}
}

func (heci *Driver) Init(useLME bool, useWD bool) error {
	var err error

	heci.meiDevice, err = os.OpenFile(Device, syscall.O_RDWR, 0)
	if err != nil {
		if err.Error() == "open /dev/mei0: permission denied" {
			log.Error("need administrator privileges")
		} else if err.Error() == "open /dev/mei0: no such file or directory" {
			log.Error("AMT not found: MEI/driver is missing or the call to the HECI driver failed")
		} else {
			log.Error("Cannot open MEI Device")
		}

		return err
	}

	data := CMEIConnectClientData{}
	if useWD {
		data.data = MEI_WDIF
	} else if useLME {
		data.data = MEI_LMEIF
	} else {
		data.data = MEI_IAMTHIF
	}

	// we try up to 3 times in case the resource/device is still busy from previous call.
	for i := 0; i < 3; i++ {
		err = Ioctl(heci.meiDevice.Fd(), IOCTL_MEI_CONNECT_CLIENT, uintptr(unsafe.Pointer(&data)))
		if err == nil {
			break
		}
	}

	if err != nil {
		return err
	}

	t := MEIConnectClientData{}

	err = binary.Read(bytes.NewBuffer(data.data[:]), binary.LittleEndian, &t)
	if err != nil {
		return err
	}

	heci.bufferSize = t.MaxMessageLength
	heci.protocolVersion = t.ProtocolVersion //should be 4?

	return nil
}
func (heci *Driver) GetBufferSize() uint32 {
	return heci.bufferSize
}
func (heci *Driver) SendMessage(buffer []byte, done *uint32) (bytesWritten uint32, err error) {
	size, err := syscall.Write(int(heci.meiDevice.Fd()), buffer)
	if err != nil {
		return 0, err
	}

	return uint32(size), nil
}
func (heci *Driver) ReceiveMessage(buffer []byte, done *uint32) (bytesRead uint32, err error) {
	read, err := unix.Read(int(heci.meiDevice.Fd()), buffer)
	if err != nil {
		return 0, err
	}

	return uint32(read), nil
}

func Ioctl(fd, op, arg uintptr) error {
	_, _, ep := syscall.Syscall(syscall.SYS_IOCTL, fd, op, arg)
	if ep != 0 {
		return syscall.Errno(ep)
	}

	return nil
}

func (heci *Driver) Close() {
	err := heci.meiDevice.Close()
	if err != nil {
		log.Error(err)
	}
}
