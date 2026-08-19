/*********************************************************************
 * Copyright (c) Intel Corporation 2026
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/

package psr

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"fmt"

	"github.com/device-management-toolkit/rpc-go/v2/pkg/heci"
	log "github.com/sirupsen/logrus"
)

// maxReceiveChunks bounds the chunked-read loop. A PSR response carries a
// certificate chain and can exceed the MEI client's max message length, so the
// reply is drained across several ReceiveMessage calls. The bound keeps a
// misbehaving firmware from spinning here forever.
const maxReceiveChunks = 16

// Command wraps a HECI interface for PSR operations.
// Follows the same pattern as upid.Command and hotham.Command.
type Command struct {
	Heci heci.Interface
}

// GetPSR retrieves the signed Platform Service Record via MEI/HECI.
// It initializes and cleans up the HECI connection automatically.
func (c *Command) GetPSR() (*PSR, error) {
	nonce, err := newNonce()
	if err != nil {
		return nil, err
	}

	if err := c.initGUID(); err != nil {
		return nil, err
	}
	defer c.Close()

	return c.getRecord(nonce)
}

// Close releases resources held by the PSR command.
func (c *Command) Close() {
	if c.Heci != nil {
		c.Heci.Close()
	}
}

// newNonce generates the caller-supplied freshness nonce for the request.
func newNonce() ([NonceSize]byte, error) {
	var nonce [NonceSize]byte

	if _, err := rand.Read(nonce[:]); err != nil {
		return nonce, fmt.Errorf("failed to generate PSR nonce: %w", err)
	}

	return nonce, nil
}

// getRecord sends the record-get command and parses the response.
func (c *Command) getRecord(nonce [NonceSize]byte) (*PSR, error) {
	request := GetRecordRequest{
		Header: PSRHECIHeader{
			Command: CommandGetPlatformServiceRecord,
			Length:  uint32(NonceSize),
		},
		UserNonce: nonce,
	}

	var requestBuffer bytes.Buffer

	err := binary.Write(&requestBuffer, binary.LittleEndian, &request)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize PSR request: %w", err)
	}

	if err := c.send(requestBuffer.Bytes()); err != nil {
		return nil, err
	}

	response, err := c.receive()
	if err != nil {
		return nil, err
	}

	psr, err := parseGetRecordResponse(response)
	if err != nil {
		return nil, err
	}

	psr.UserNonce = nonce[:]

	return psr, nil
}

// send writes a serialized request to the PSR MEI client.
func (c *Command) send(request []byte) error {
	requestSize := uint32(len(request))

	log.Tracef("Sending PSR request: %d bytes: %x", requestSize, request)

	bytesWritten, err := c.Heci.SendMessage(request, &requestSize)
	if err != nil {
		log.Tracef("Failed to send PSR command: %v", err)

		return ErrCommandFailed
	}

	if bytesWritten != len(request) {
		return fmt.Errorf("%w: incomplete PSR request sent: %d/%d bytes", ErrCommandFailed, bytesWritten, len(request))
	}

	return nil
}

// receive drains a PSR response, which may span several MEI messages because
// the signed record carries a certificate chain.
func (c *Command) receive() ([]byte, error) {
	bufferSize := c.Heci.GetBufferSize()
	if bufferSize == 0 {
		return nil, ErrInvalidResponse
	}

	var response []byte

	for chunk := 0; chunk < maxReceiveChunks; chunk++ {
		readSize := bufferSize
		buffer := make([]byte, bufferSize)

		bytesRead, err := c.Heci.ReceiveMessage(buffer, &readSize)
		if err != nil {
			if len(response) > 0 && heci.IsReadTimeout(err) {
				break
			}

			log.Tracef("Failed to receive PSR response: %v", err)

			return nil, ErrCommandFailed
		}

		if bytesRead <= 0 {
			break
		}

		response = append(response, buffer[:bytesRead]...)

		// Stop once the header's declared length has been satisfied.
		if complete, err := responseComplete(response); err != nil {
			return nil, err
		} else if complete {
			break
		}
	}

	if len(response) == 0 {
		return nil, fmt.Errorf("%w: empty response from PSR MEI client", ErrInvalidResponse)
	}

	log.Tracef("PSR response: %d bytes received", len(response))

	return response, nil
}

// responseComplete reports whether the accumulated bytes cover the length
// declared in the response header. It returns false while the header itself is
// still incomplete.
func responseComplete(response []byte) (bool, error) {
	if len(response) < HeaderSize {
		return false, nil
	}

	header, err := parseHeader(response)
	if err != nil {
		return false, err
	}

	return uint64(len(response)) >= uint64(HeaderSize)+uint64(header.Length), nil
}

// parseHeader decodes the PSR HECI header from the front of a response.
func parseHeader(response []byte) (PSRHECIHeader, error) {
	var header PSRHECIHeader

	err := binary.Read(bytes.NewReader(response[:HeaderSize]), binary.LittleEndian, &header)
	if err != nil {
		return header, fmt.Errorf("failed to parse PSR response header: %w", err)
	}

	return header, nil
}

// parseGetRecordResponse decodes the header and status of a record-get
// response and retains the remainder verbatim for later field extraction.
func parseGetRecordResponse(response []byte) (*PSR, error) {
	if len(response) < MinResponseSize {
		return nil, fmt.Errorf("%w: PSR response too short: %d bytes (expected at least %d)",
			ErrInvalidResponse, len(response), MinResponseSize)
	}

	header, err := parseHeader(response)
	if err != nil {
		return nil, err
	}

	if header.Command != CommandGetPlatformServiceRecord {
		return nil, fmt.Errorf("%w: unexpected command in response: %d (expected %d)",
			ErrInvalidResponse, header.Command, CommandGetPlatformServiceRecord)
	}

	status := binary.LittleEndian.Uint32(response[HeaderSize:MinResponseSize])

	log.Tracef("PSR header: Command=%d Length=%d Status=%d", header.Command, header.Length, status)

	if status != StatusSuccess {
		return nil, mapStatusError(status)
	}

	return &PSR{
		Status:  status,
		Raw:     response,
		Payload: response[MinResponseSize:],
	}, nil
}

// mapStatusError converts an Intel PSR status code to a Go error.
//
// Only StatusSuccess is currently known. Extend this with the documented PSR
// status codes — particularly the not-supported and not-enabled cases, which
// callers are expected to treat as ordinary outcomes.
func mapStatusError(status uint32) error {
	log.Tracef("PSR command returned error status: %d", status)

	return fmt.Errorf("%w with status: 0x%08x", ErrCommandFailed, status)
}
