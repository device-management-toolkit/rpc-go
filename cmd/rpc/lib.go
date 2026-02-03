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

	"github.com/device-management-toolkit/rpc-go/v2/pkg/utils"
	log "github.com/sirupsen/logrus"
)

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

	// Save the current stdout and redirect temporarily
	oldStdout := os.Stdout
	outR, outW, _ := os.Pipe()
	os.Stdout = outW

	// Save the current stderr and redirect temporarily
	oldStderr := os.Stderr
	os.Stderr = outW

	// Redirect logger output too to avoid printing from rpc library
	log.SetOutput(outW)

	if accessStatus := rpcCheckAccess(); accessStatus != int(utils.Success) {
		log.Error(AccessErrMsg)
		captureAndRestoreOutput(outW, outR, oldStdout, oldStderr, Output)

		return accessStatus
	}

	// create argument array from input string
	inputString := C.GoString(Input)
	// Split string
	r := csv.NewReader(strings.NewReader(inputString))
	r.Comma = ' ' // space

	args, err := r.Read()
	if err != nil {
		log.Error(err.Error())
		captureAndRestoreOutput(outW, outR, oldStdout, oldStderr, Output)

		return utils.InvalidParameterCombination.Code
	}

	args = append([]string{"rpc"}, args...)

	err = runRPC(args)
	if err != nil {
		log.Error("rpcExec failed: " + inputString)
		errCode := handleError(err)
		captureAndRestoreOutput(outW, outR, oldStdout, oldStderr, Output)

		return errCode
	}

	captureAndRestoreOutput(outW, outR, oldStdout, oldStderr, Output)

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

func captureAndRestoreOutput(writeFile *os.File, readFile *os.File, oldStdout *os.File, oldStderr *os.File, Output **C.char) {
	writeFile.Close()
	var outBuf bytes.Buffer
	io.Copy(&outBuf, readFile)
	os.Stdout = oldStdout
	os.Stderr = oldStderr
	*Output = C.CString(outBuf.String())
}
