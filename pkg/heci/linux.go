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
	"time"
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

// ResetMEIDevice attempts to reset MEI device state by waiting for it to become available
func (heci *Driver) ResetMEIDevice() error {
	if heci.meiDevice != nil {
		heci.meiDevice.Close()
		heci.meiDevice = nil
	}

	log.Debug("Waiting for MEI device to reset...")
	time.Sleep(10 * time.Second)

	return nil
}

func (heci *Driver) Init(useLME, useWD bool) error {
	var err error

	// Close existing connection if switching to LME to ensure clean state
	if heci.meiDevice != nil && useLME {
		heci.meiDevice.Close()
		heci.meiDevice = nil

		time.Sleep(3 * time.Second)
	}

	// For PTHI/WD, always reopen to ensure fresh connection
	// For LME, only open if not already open
	if !useLME || heci.meiDevice == nil {
		// Close any existing connection for PTHI
		if heci.meiDevice != nil && !useLME {
			heci.meiDevice.Close()
			heci.meiDevice = nil
		}

		// Open MEI device with retry for device busy
		for attempt := 1; attempt <= 2; attempt++ {
			heci.meiDevice, err = os.OpenFile(Device, syscall.O_RDWR, 0)
			if err == nil {
				break
			}

			if err.Error() == "open /dev/mei0: permission denied" {
				log.Error("need administrator privileges")

				return err
			} else if err.Error() == "open /dev/mei0: no such file or directory" {
				log.Error("AMT not found: MEI/driver is missing or the call to the HECI driver failed")

				return err
			} else if err.Error() == "open /dev/mei0: device or resource busy" && attempt == 1 {
				log.Debug("MEI device busy, waiting before retry...")
				time.Sleep(5 * time.Second)

				continue
			} else {
				log.Error("Cannot open MEI Device")

				return err
			}
		}
	}

	data := CMEIConnectClientData{}
	if useWD {
		data.data = MEI_WDIF
	} else if useLME {
		data.data = MEI_LMEIF
	} else {
		data.data = MEI_IAMTHIF
	}

	err = Ioctl(heci.meiDevice.Fd(), IOCTL_MEI_CONNECT_CLIENT, uintptr(unsafe.Pointer(&data)))
	if err != nil {
		return err
	}

	t := MEIConnectClientData{}

	err = binary.Read(bytes.NewBuffer(data.data[:]), binary.LittleEndian, &t)
	if err != nil {
		return err
	}

	heci.bufferSize = t.MaxMessageLength
	heci.protocolVersion = t.ProtocolVersion // should be 4?

	return nil
}

func (heci *Driver) GetBufferSize() uint32 {
	return heci.bufferSize
}

func (heci *Driver) SendMessage(buffer []byte, done *uint32) (bytesWritten int, err error) {
	// Validate file descriptor before attempting write
	if heci.meiDevice == nil {
		return 0, syscall.EBADF
	}

	// Retry write operations on interrupted system call
	for i := 0; i < 3; i++ {
		size, err := syscall.Write(int(heci.meiDevice.Fd()), buffer)
		if err == nil {
			return size, nil
		}

		// Retry on interrupted system call
		if err == syscall.EINTR {
			time.Sleep(50 * time.Millisecond)

			continue
		}

		return 0, err
	}

	return 0, syscall.EINTR
}

func (driver *Driver) ReceiveMessage(buffer []byte, done *uint32) (bytesRead int, err error) {
	// Validate file descriptor before attempting read
	if driver.meiDevice == nil {
		return 0, syscall.EBADF
	}

	// Retry read operations on interrupted system call
	for i := 0; i < 3; i++ {
		read, err := unix.Read(int(driver.meiDevice.Fd()), buffer)
		if err == nil {
			return read, nil
		}

		// Retry on interrupted system call
		if err == syscall.EINTR {
			time.Sleep(50 * time.Millisecond)

			continue
		}

		return 0, err
	}

	return 0, syscall.EINTR
}

func Ioctl(fd, op, arg uintptr) error {
	// Retry IOCTL on interrupted system call (EINTR)
	for i := 0; i < 3; i++ {
		_, _, ep := syscall.Syscall(syscall.SYS_IOCTL, fd, op, arg)
		if ep == 0 {
			return nil
		}

		// Retry on interrupted system call (EINTR = 4)
		if ep == syscall.EINTR {
			time.Sleep(100 * time.Millisecond)

			continue
		}

		return ep
	}

	return syscall.EINTR
}

func (heci *Driver) Close() {
	err := heci.meiDevice.Close()
	if err != nil {
		log.Error(err)
	}
}
