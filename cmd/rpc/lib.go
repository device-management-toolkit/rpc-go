/*********************************************************************
 * Copyright (c) Intel Corporation 2021
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/
package main

// NOTE: this file is designed to be built into a C library and the import
// of 'C' introduces a dependency on the gcc toolchain

import "C"

import (
	"bytes"
	"encoding/csv"
	"io"
	"os"
	"strings"
	"sync"

	"github.com/device-management-toolkit/rpc-go/v2/pkg/utils"
	log "github.com/sirupsen/logrus"
)

// ThreadSafeWriter is a thread-safe writer that collects output
type ThreadSafeWriter struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (w *ThreadSafeWriter) Write(p []byte) (n int, err error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.buf.Write(p)
}

func (w *ThreadSafeWriter) String() string {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.buf.String()
}

//export rpcCheckAccess
func rpcCheckAccess() int {
	err := checkAccess()
	if err != nil {
		return handleError(err)
	}

	return int(utils.Success)
}

//export rpcExec
func rpcExec(Input *C.char, Output **C.char) int {
	defer func() {
		if r := recover(); r != nil {
			println("Recovered panic: %v", r)
		}
	}()

	// Save the current stdout, stderr, and logger output
	oldStdout := os.Stdout
	oldStderr := os.Stderr
	oldLogOutput := log.StandardLogger().Out

	// Create pipes to capture output
	rOut, wOut, err := os.Pipe()
	if err != nil {
		log.Error("Failed to create stdout pipe:", err)
		*Output = C.CString("")
		return utils.GenericFailure.Code
	}
	rErr, wErr, err := os.Pipe()
	if err != nil {
		log.Error("Failed to create stderr pipe:", err)
		*Output = C.CString("")
		return utils.GenericFailure.Code
	}

	// Create a thread-safe writer to collect all output
	outputWriter := &ThreadSafeWriter{}

	// Redirect stdout, stderr, and logger
	os.Stdout = wOut
	os.Stderr = wErr
	log.SetOutput(wOut)

	// Use WaitGroup to track goroutines
	var wg sync.WaitGroup
	wg.Add(2)

	// Goroutine to read from stdout pipe
	go func() {
		defer wg.Done()
		io.Copy(outputWriter, rOut)
	}()

	// Goroutine to read from stderr pipe
	go func() {
		defer wg.Done()
		io.Copy(outputWriter, rErr)
	}()

	// Ensure everything is restored and output is captured
	defer func() {
		// Close write ends of pipes to signal EOF to readers
		wOut.Close()
		wErr.Close()

		// Wait for all readers to finish
		wg.Wait()

		// Restore original outputs
		os.Stdout = oldStdout
		os.Stderr = oldStderr
		log.SetOutput(oldLogOutput)

		// Close read ends
		rOut.Close()
		rErr.Close()

		// Set the output
		*Output = C.CString(outputWriter.String())
	}()

	if accessStatus := rpcCheckAccess(); accessStatus != int(utils.Success) {
		log.Error(AccessErrMsg)
		return accessStatus
	}

	// create argument array from input string
	inputString := C.GoString(Input)
	// Split string
	r := csv.NewReader(strings.NewReader(inputString))
	r.Comma = ' ' // space

	args, readErr := r.Read()
	if readErr != nil {
		log.Error(readErr.Error())
		return utils.InvalidParameterCombination.Code
	}

	args = append([]string{"rpc"}, args...)

	execErr := runRPC(args)
	if execErr != nil {
		log.Error("rpcExec failed: " + inputString)
		return handleError(execErr)
	}

	return int(utils.Success)
}

func handleError(err error) int {
	if customErr, ok := err.(utils.CustomError); ok {
		log.Error(customErr.Error())

		return customErr.Code
	} else {
		log.Error(err.Error())

		return utils.GenericFailure.Code
	}
}
