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
	"errors"
	"os"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"github.com/device-management-toolkit/rpc-go/v2/pkg/utils"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"
)

type Driver struct {
	meiDevice       *os.File
	bufferSize      uint32
	protocolVersion uint8
	useLME          bool
	useWD           bool
	// Issue #6 fix: Add mutex to protect device handle access
	mu sync.RWMutex
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

func (heci *Driver) Init(useLME, useWD bool) error {
	heci.useLME = useLME
	heci.useWD = useWD

	var err error

	// Close any previous device handle before reopening
	if heci.meiDevice != nil {
		_ = heci.meiDevice.Close()
		heci.meiDevice = nil
	}

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

	// retry with backoff in case the device is busy after a reset
	for i := 0; i < 5; i++ {
		err = Ioctl(heci.meiDevice.Fd(), IOCTL_MEI_CONNECT_CLIENT, uintptr(unsafe.Pointer(&data)))
		if err == nil {
			break
		}

		if errors.Is(err, syscall.EBUSY) {
			log.Warnf("mei connect busy, retry %d", i+1)
			time.Sleep(time.Duration(i+1) * utils.HeciConnectRetryBackoff * time.Millisecond)
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
	heci.protocolVersion = t.ProtocolVersion // should be 4?

	return nil
}

func (heci *Driver) GetBufferSize() uint32 {
	return heci.bufferSize
}

func (heci *Driver) SendMessage(buffer []byte, done *uint32) (bytesWritten int, err error) {
	log.Tracef("heci send len=%d", len(buffer))

	// Issue #6 fix: Protect device handle access with read lock
	heci.mu.RLock()
	fd := int(heci.meiDevice.Fd())
	heci.mu.RUnlock()

	size, err := syscall.Write(fd, buffer)
	if err != nil {
		if errors.Is(err, syscall.ENODEV) || err.Error() == "no such device" {
			log.Warn("mei device unavailable, reinitializing")

			// Issue #6 fix: Use write lock during reinitialization
			heci.mu.Lock()
			_ = heci.meiDevice.Close()

			time.Sleep(utils.HeciRetryDelay * time.Millisecond)

			if initErr := heci.Init(heci.useLME, heci.useWD); initErr != nil {
				heci.mu.Unlock()
				return 0, initErr
			}
			fd = int(heci.meiDevice.Fd())
			heci.mu.Unlock()

			size, err = syscall.Write(fd, buffer)
		}

		// Issue #5 fix: Increase EBUSY retry attempts from 1 to 3 with exponential backoff
		if errors.Is(err, syscall.EBUSY) {
			for attempt := 0; attempt < 3; attempt++ {
				log.Warnf("mei write busy, retrying (attempt %d/3)", attempt+1)
				delay := time.Duration(attempt+1) * utils.HeciRetryDelay * time.Millisecond
				time.Sleep(delay)

				heci.mu.RLock()
				fd = int(heci.meiDevice.Fd())
				heci.mu.RUnlock()

				size, err = syscall.Write(fd, buffer)
				if !errors.Is(err, syscall.EBUSY) {
					break
				}
			}
		}

		if err != nil {
			return 0, err
		}
	}

	return size, nil
}

func (driver *Driver) ReceiveMessage(buffer []byte, done *uint32) (bytesRead int, err error) {
	// Issue #6 fix: Protect device handle access with read lock
	driver.mu.RLock()
	fd := int(driver.meiDevice.Fd())
	driver.mu.RUnlock()

	deadline := time.Now().Add(utils.HeciReadTimeout * time.Second)

	for {
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return 0, errors.New("heci read timeout")
		}

		timeoutMs := int(remaining.Milliseconds())
		if timeoutMs == 0 {
			timeoutMs = 1
		}

		pfd := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}

		n, pollErr := unix.Poll(pfd, timeoutMs)
		if pollErr != nil {
			if pollErr == unix.EINTR {
				continue
			}

			return 0, pollErr
		}

		if n == 0 {
			return 0, errors.New("heci read timeout")
		}

		if pfd[0].Revents&unix.POLLIN != 0 {
			log.Tracef("heci poll revents=0x%x", pfd[0].Revents)

			read, readErr := unix.Read(fd, buffer)
			if readErr == unix.EINTR {
				continue
			}

			return read, readErr
		}

		if pfd[0].Revents&(unix.POLLERR|unix.POLLHUP|unix.POLLNVAL) != 0 {
			log.Warnf("heci poll error revents=0x%x; reinitializing", pfd[0].Revents)

			// Issue #6 fix: Use write lock during reinitialization
			driver.mu.Lock()
			_ = driver.meiDevice.Close()

			time.Sleep(utils.HeciReinitDelay * time.Millisecond)

			if initErr := driver.Init(driver.useLME, driver.useWD); initErr != nil {
				driver.mu.Unlock()
				return 0, initErr
			}

			fd = int(driver.meiDevice.Fd())
			deadline = time.Now().Add(utils.HeciReadTimeout * time.Second)
			driver.mu.Unlock()

			continue
		}
	}
}

func Ioctl(fd, op, arg uintptr) error {
	_, _, ep := syscall.Syscall(syscall.SYS_IOCTL, fd, op, arg)
	if ep != 0 {
		return ep
	}

	return nil
}

func (heci *Driver) Close() {
	// Protect against concurrent close operations
	heci.mu.Lock()
	defer heci.mu.Unlock()

	if heci.meiDevice != nil {
		err := heci.meiDevice.Close()
		if err != nil {
			log.Error(err)
		}
		heci.meiDevice = nil
	}
}
