//go:build !windows

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
	"io/fs"
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
	useGUIDClient   bool
	// Protect device handle access across concurrent Send/Receive/reinit/Close paths.
	mu sync.RWMutex
	// Throttle repeated poll warning logs during transient device instability.
	lastPollWarnLogTime time.Time
	suppressedPollWarns int
}

const (
	Device                   = "/dev/mei0"
	IOCTL_MEI_CONNECT_CLIENT = 0xC0104801
	pollWarnLogInterval      = 15 * time.Second
	// heciConnectAttempts bounds the MEI_CONNECT_CLIENT EBUSY retry loop.
	// Connect almost always succeeds on retry 1 after a reopen; the extra
	// attempts only cover the rarer cases where the ME stays busy. The
	// backoff ramps per attempt (HeciConnectRetryBackoff * (i+1)) so repeated
	// "mei connect busy" retries are spaced further apart as the ME settles.
	heciConnectAttempts = 8
	// guidConnectAttempts bounds the MEI_CONNECT_CLIENT retry loop for the
	// GUID-targeted clients (InitWithGUID / InitHOTHAM). These paths are not
	// EBUSY-tuned like initLocked; a small fixed number of attempts is enough.
	guidConnectAttempts = 3
	// heciWriteBusyAttempts bounds the EBUSY retry loop around a HECI write.
	heciWriteBusyAttempts = 3
)

// meiDevicePaths lists the MEI character devices probed in order. Mirrors the
// LMS client, which tries /dev/mei0 through /dev/mei3 and uses the first device
// that exposes the requested client GUID.
var meiDevicePaths = []string{"/dev/mei0", "/dev/mei1", "/dev/mei2", "/dev/mei3"}

// PTHI
var MEI_IAMTHIF = [16]uint8{0x28, 0x00, 0xf8, 0x12, 0xb7, 0xb4, 0x2d, 0x4b, 0xac, 0xa8, 0x46, 0xe0, 0xff, 0x65, 0x81, 0x4c}

// LME
var MEI_LMEIF = [16]uint8{0xdb, 0xa4, 0x33, 0x67, 0x76, 0x04, 0x7b, 0x4e, 0xb3, 0xaf, 0xbc, 0xfc, 0x29, 0xbe, 0xe7, 0xa7}

// Watchdog (WD)
var MEI_WDIF = [16]uint8{0x6f, 0x9a, 0xb7, 0x05, 0x28, 0x46, 0x7f, 0x4d, 0x89, 0x9D, 0xA9, 0x15, 0x14, 0xCB, 0x32, 0xAB}

// UPID (Unique Platform ID)
var MEI_UPID = [16]uint8{0x79, 0x6c, 0x13, 0x92, 0xea, 0x5f, 0xfd, 0x4c, 0x98, 0x0e, 0x23, 0xbe, 0x07, 0xfa, 0x5e, 0x9f}

// HOTHAM GUID
// GUID: {082EE5A7-7C25-470A-9643-0C06F0466EA1}
var MEI_HOTHAM = [16]uint8{0xa7, 0xe5, 0x2e, 0x08, 0x25, 0x7c, 0x0a, 0x47, 0x96, 0x43, 0x0c, 0x06, 0xf0, 0x46, 0x6e, 0xa1}

// formatGUID formats a [16]uint8 GUID array as a standard GUID string
func formatGUID(guid [16]uint8) string {
	return fmt.Sprintf("{%02X%02X%02X%02X-%02X%02X-%02X%02X-%02X%02X-%02X%02X%02X%02X%02X%02X}",
		guid[3], guid[2], guid[1], guid[0],
		guid[5], guid[4],
		guid[7], guid[6],
		guid[8], guid[9],
		guid[10], guid[11], guid[12], guid[13], guid[14], guid[15])
}

func NewDriver() *Driver {
	return &Driver{}
}

// Init configures the HECI driver for IAMTHIF, LME, or WD operation.
func (heci *Driver) Init(useLME, useWD bool) error {
	heci.mu.Lock()
	defer heci.mu.Unlock()

	return heci.initLocked(useLME, useWD)
}

// openMEIDevicePath closes any previously opened MEI handle and opens the given
// device node, classifying the failure for logging. Shared by the device-probe
// loop so the close-then-reopen and error-classification logic lives in one
// place. Failures are logged at debug because probing missing nodes is expected
// while iterating /dev/mei0..3; the overall failure is surfaced by openAndConnect.
func (heci *Driver) openMEIDevicePath(path string) error {
	if heci.meiDevice != nil {
		_ = heci.meiDevice.Close()
		heci.meiDevice = nil
	}

	dev, err := os.OpenFile(path, syscall.O_RDWR, 0)
	if err != nil {
		switch {
		case errors.Is(err, fs.ErrPermission):
			log.Debugf("need administrator privileges to open %s", path)
		case errors.Is(err, fs.ErrNotExist):
			log.Debugf("%s not present", path)
		default:
			log.Debugf("cannot open %s: %v", path, err)
		}

		return err
	}

	heci.meiDevice = dev

	return nil
}

// connectClient issues MEI_CONNECT_CLIENT on the currently open device for the
// GUID in data. It retries up to attempts times; when ramp is true the backoff
// grows per attempt and only EBUSY is retried (the IAMTHIF/LME/WD path),
// otherwise every failure is retried immediately (GUID-targeted clients).
func (heci *Driver) connectClient(data *CMEIConnectClientData, attempts int, ramp bool) error {
	var err error

	for i := 0; i < attempts; i++ {
		err = Ioctl(heci.meiDevice.Fd(), IOCTL_MEI_CONNECT_CLIENT, uintptr(unsafe.Pointer(data)))
		if err == nil {
			return nil
		}

		if !ramp {
			continue
		}

		// Only a busy device is worth retrying; any other error won't clear by
		// waiting. Don't sleep after the final attempt - there's no retry left.
		if !errors.Is(err, syscall.EBUSY) || i == attempts-1 {
			break
		}

		// Per-attempt busy is an expected transient (the ME settles within a few
		// retries); log at debug so it only shows under -v.
		log.Debugf("mei connect busy, retry %d", i+1)
		time.Sleep(time.Duration(i+1) * utils.HeciConnectRetryBackoff * time.Millisecond)
	}

	return err
}

// openAndConnect probes meiDevicePaths in order, mirroring the LMS client. For
// each node it opens the device and attempts to connect the client GUID in
// data. A node that is absent/inaccessible, or present but not hosting the
// requested client, is skipped and the next node is tried. A busy device stops
// the probe (like LMS breaking out on TEE_BUSY) because another node won't
// clear it. On success the connected handle is left open on the driver.
func (heci *Driver) openAndConnect(data *CMEIConnectClientData, attempts int, ramp bool) error {
	var lastErr error

	for _, path := range meiDevicePaths {
		if err := heci.openMEIDevicePath(path); err != nil {
			// Avoid masking earlier errors (eg permission denied) with a later
			// fs.ErrNotExist from trailing probe paths.
			if lastErr == nil || errors.Is(lastErr, fs.ErrNotExist) {
				lastErr = err
			}

			continue
		}

		if err := heci.connectClient(data, attempts, ramp); err != nil {
			lastErr = err

			if errors.Is(err, syscall.EBUSY) {
				break
			}

			continue
		}

		return nil
	}

	// No device connected; drop any dangling handle from the last probe.
	if heci.meiDevice != nil {
		_ = heci.meiDevice.Close()
		heci.meiDevice = nil
	}

	if lastErr != nil && errors.Is(lastErr, fs.ErrNotExist) {
		log.Error("AMT not found: MEI/driver is missing or the call to the HECI driver failed")
	}

	return lastErr
}

// parseConnectClientData reads the MEI_CONNECT_CLIENT response out of data and
// records the negotiated buffer size and protocol version on the driver. Shared
// by every Init* entry point.
func (heci *Driver) parseConnectClientData(data CMEIConnectClientData) error {
	t := MEIConnectClientData{}

	err := binary.Read(bytes.NewBuffer(data.data[:]), binary.LittleEndian, &t)
	if err != nil {
		return err
	}

	heci.bufferSize = t.MaxMessageLength
	heci.protocolVersion = t.ProtocolVersion

	return nil
}

func (heci *Driver) initLocked(useLME, useWD bool) error {
	heci.useLME = useLME
	heci.useWD = useWD
	heci.useGUIDClient = false

	data := CMEIConnectClientData{}
	if useWD {
		data.data = MEI_WDIF
	} else if useLME {
		data.data = MEI_LMEIF
	} else {
		data.data = MEI_IAMTHIF
	}

	// Probe /dev/mei0..3 (LMS-style) and connect the client on the first device
	// that hosts it. EBUSY is retried per device with a ramped backoff: the ME
	// is typically ready within a few ms of a reopen and connect succeeds on the
	// first retry, so the backoff starts short and ramps up only for the rarer
	// cases where the device stays busy longer.
	err := heci.openAndConnect(&data, heciConnectAttempts, true)
	if err != nil {
		if errors.Is(err, syscall.EBUSY) {
			log.Warnf("mei connect still busy after %d attempts", heciConnectAttempts)
		}

		return err
	}

	return heci.parseConnectClientData(data)
}

// InitWithGUID initializes the HECI driver with a specific GUID
func (heci *Driver) InitWithGUID(guid interface{}) error {
	heci.mu.Lock()
	defer heci.mu.Unlock()

	heci.useLME = false
	heci.useWD = false
	heci.useGUIDClient = true

	// Type assert to [16]uint8
	guidBytes, ok := guid.([16]uint8)
	if !ok {
		return errors.New("invalid GUID type for Linux, expected [16]uint8")
	}

	data := CMEIConnectClientData{}
	data.data = guidBytes

	// Probe /dev/mei0..3 (LMS-style) for the device hosting this client GUID.
	if err := heci.openAndConnect(&data, guidConnectAttempts, false); err != nil {
		return err
	}

	return heci.parseConnectClientData(data)
}

// InitHOTHAM configures the HECI driver for the HOTHAM GUID interface.
func (heci *Driver) InitHOTHAM() error {
	heci.mu.Lock()
	defer heci.mu.Unlock()

	heci.useLME = false
	heci.useWD = false
	heci.useGUIDClient = true

	data := CMEIConnectClientData{}
	data.data = MEI_HOTHAM

	// Probe /dev/mei0..3 (LMS-style) for the device hosting the HOTHAM client.
	if err := heci.openAndConnect(&data, guidConnectAttempts, false); err != nil {
		log.Errorf("InitHOTHAM: Failed to connect to HOTHAM GUID after %d attempts: %v", guidConnectAttempts, err)

		return err
	}

	if err := heci.parseConnectClientData(data); err != nil {
		log.Errorf("InitHOTHAM: Failed to parse connection data: %v", err)

		return err
	}

	log.Tracef("InitHOTHAM: Connected to HOTHAM GUID: %s, Buffer size: %d, Protocol version: %d",
		formatGUID(MEI_HOTHAM), heci.bufferSize, heci.protocolVersion)

	return nil
}

// GetBufferSize returns the max message size negotiated with the HECI client.
func (heci *Driver) GetBufferSize() uint32 {
	return heci.bufferSize
}

// SendMessage writes a payload to the active HECI interface.
func (heci *Driver) SendMessage(buffer []byte, done *uint32) (bytesWritten int, err error) {
	// Hold read lock for fd lookup + write to avoid close/re-init races.
	heci.mu.RLock()

	if heci.meiDevice == nil {
		heci.mu.RUnlock()

		return 0, ErrDeviceNotInitialized
	}

	fd := int(heci.meiDevice.Fd())
	size, err := syscall.Write(fd, buffer)

	heci.mu.RUnlock()

	if err != nil {
		if errors.Is(err, syscall.ENODEV) || err.Error() == "no such device" {
			log.Warn("mei device unavailable, reinitializing, and retrying write")
			// Brief settle to let the kernel finish tearing down the closed
			// fd before reopen. initLocked retries MEI_CONNECT_CLIENT on EBUSY
			// with its own ramped backoff, so this only needs to cover the
			// teardown - not the full reinit delay that used to pad every
			// post-keygen reinit by half a second.
			time.Sleep(utils.HeciReopenSettleDelay * time.Millisecond)
			// Use write lock during reinitialization.
			heci.mu.Lock()

			if heci.meiDevice != nil {
				_ = heci.meiDevice.Close()
				heci.meiDevice = nil
			}

			if heci.useGUIDClient {
				heci.mu.Unlock()

				return 0, ErrDeviceNotInitialized
			}

			if initErr := heci.initLocked(heci.useLME, heci.useWD); initErr != nil {
				heci.mu.Unlock()

				return 0, initErr
			}

			// In LME mode the firmware also resets the APF session on reinit
			// (it replays PROTOCOL_VERSION + tcpip-forwards), so the caller's
			// in-flight channel id is now stale. Surface that explicitly
			// instead of silently replaying the original write.
			if heci.useLME {
				heci.mu.Unlock()

				return 0, ErrDeviceReinitialized
			}

			fd = int(heci.meiDevice.Fd())
			size, err = syscall.Write(fd, buffer)

			heci.mu.Unlock()
		}

		// Increase EBUSY retry attempts from 1 to 3 with exponential backoff.
		if errors.Is(err, syscall.EBUSY) {
			for attempt := 0; attempt < heciWriteBusyAttempts; attempt++ {
				// Expected transient; debug-only so it doesn't spam without -v.
				log.Debugf("mei write busy, retrying (attempt %d/%d)", attempt+1, heciWriteBusyAttempts)
				delay := time.Duration(attempt+1) * utils.HeciRetryDelay * time.Millisecond
				time.Sleep(delay)

				heci.mu.RLock()

				if heci.meiDevice == nil {
					heci.mu.RUnlock()

					return 0, ErrDeviceNotInitialized
				}

				fd = int(heci.meiDevice.Fd())
				size, err = syscall.Write(fd, buffer)

				heci.mu.RUnlock()

				if !errors.Is(err, syscall.EBUSY) {
					break
				}
			}

			if errors.Is(err, syscall.EBUSY) {
				log.Warnf("mei write still busy after %d attempts", heciWriteBusyAttempts)
			}
		}

		if err != nil {
			return 0, err
		}
	}

	return size, nil
}

// ReceiveMessage reads a payload from the active HECI interface.
func (heci *Driver) ReceiveMessage(buffer []byte, done *uint32) (bytesRead int, err error) {
	deadline := time.Now().Add(utils.HeciReadTimeout * time.Second)

	for {
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return 0, ErrReadTimeout
		}

		timeoutMs := int(remaining.Milliseconds())
		if timeoutMs == 0 {
			timeoutMs = 1
		}

		heci.mu.RLock()

		if heci.meiDevice == nil {
			heci.mu.RUnlock()

			return 0, ErrDeviceNotInitialized
		}

		fd := int(heci.meiDevice.Fd())
		heci.mu.RUnlock()

		pfd := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}

		n, pollErr := unix.Poll(pfd, timeoutMs)
		if pollErr != nil {
			if pollErr == unix.EINTR {
				continue
			}

			if pollErr == unix.EBADF {
				return 0, ErrDeviceNotInitialized
			}

			return 0, pollErr
		}

		if n == 0 {
			return 0, ErrReadTimeout
		}

		if pfd[0].Revents&unix.POLLIN != 0 {
			read, readErr := unix.Read(fd, buffer)

			if readErr == unix.EINTR {
				continue
			}

			if readErr == unix.EBADF {
				return 0, ErrDeviceNotInitialized
			}

			return read, readErr
		}

		if pfd[0].Revents&(unix.POLLERR|unix.POLLHUP|unix.POLLNVAL) != 0 {
			heci.logPollReinitWarning(pfd[0].Revents)

			// Use write lock during reinitialization.
			heci.mu.Lock()

			if heci.meiDevice == nil {
				heci.mu.Unlock()

				return 0, ErrDeviceNotInitialized
			}

			if heci.meiDevice != nil {
				_ = heci.meiDevice.Close()
				heci.meiDevice = nil
			}

			if heci.useGUIDClient {
				heci.mu.Unlock()

				return 0, ErrDeviceNotInitialized
			}

			time.Sleep(utils.HeciReinitDelay * time.Millisecond)

			if initErr := heci.initLocked(heci.useLME, heci.useWD); initErr != nil {
				heci.mu.Unlock()

				return 0, initErr
			}

			deadline = time.Now().Add(utils.HeciReadTimeout * time.Second)

			heci.mu.Unlock()

			// In LME mode the firmware resets the APF session on reinit (it
			// replays PROTOCOL_VERSION + tcpip-forwards), so any in-flight
			// channel id is now stale. Surface that explicitly - mirroring the
			// SendMessage ENODEV path - so the caller replays the handshake and
			// re-opens the channel instead of silently waiting on a confirmation
			// that will never arrive. LMS has no APF session, so it keeps
			// transparently retrying.
			if heci.useLME {
				return 0, ErrDeviceReinitialized
			}

			continue
		}
	}
}

func (heci *Driver) logPollReinitWarning(revents int16) {
	heci.mu.Lock()
	defer heci.mu.Unlock()

	now := time.Now()
	if heci.lastPollWarnLogTime.IsZero() || now.Sub(heci.lastPollWarnLogTime) >= pollWarnLogInterval {
		if heci.suppressedPollWarns > 0 {
			log.Warnf("heci poll warn revents=0x%x; reinitializing (suppressed %d similar events)", revents, heci.suppressedPollWarns)
			heci.suppressedPollWarns = 0
		} else {
			log.Warnf("heci poll warn revents=0x%x; reinitializing", revents)
		}

		heci.lastPollWarnLogTime = now

		return
	}

	heci.suppressedPollWarns++
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
