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

	"github.com/device-management-toolkit/rpc-go/v2/internal/cli"
	"github.com/device-management-toolkit/rpc-go/v2/pkg/amt"
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
func rpcExec(Input *C.char, Output **C.char, ErrOutput **C.char) int {
	// Configure logger
	log.SetOutput(os.Stderr)

	// Save the current stdout and redirect temporarily
	oldStdout := os.Stdout
	outR, outW, _ := os.Pipe()
	os.Stdout = outW

	// Save the current stderr and redirect temporarily
	oldStderr := os.Stderr
	errR, errW, _ := os.Pipe()
	os.Stderr = errW

	captureAndRestoreStdout := func() {
		outW.Close()
		var outBuf bytes.Buffer
		io.Copy(&outBuf, outR)
		os.Stdout = oldStdout
		*Output = C.CString(outBuf.String())
	}

	captureAndRestoreStderr := func() {
		errW.Close()
		var errBuf bytes.Buffer
		io.Copy(&errBuf, errR)
		os.Stderr = oldStderr
		*ErrOutput = C.CString(errBuf.String())
	}

	amtCommand := amt.NewAMTCommand()
	err := amtCommand.Initialize()
	if err != nil {
		log.Error(AccessErrMsg)
		captureAndRestoreStderr()
		return handleError(err)
	}

	// create argument array from input string
	inputString := C.GoString(Input)
	// Split string
	r := csv.NewReader(strings.NewReader(inputString))
	r.Comma = ' ' // space

	args, err := r.Read()
	if err != nil {
		log.Error(err.Error())
		captureAndRestoreStderr()
		return utils.InvalidParameterCombination.Code
	}

	args = append([]string{"rpc"}, args...)

	// Use Kong-based CLI execution path
	err = cli.ExecuteWithAMT(args, amtCommand)
	if err != nil {
		log.Error("rpcExec failed: " + inputString)
		errCode := handleError(err)
		captureAndRestoreStderr()

		return errCode
	}

	// Save captured output to Output variable and restore stdout
	captureAndRestoreStdout()
	captureAndRestoreStderr()

	return int(utils.Success)
}

func handleError(err error) int {
	if customErr, ok := err.(utils.CustomError); ok {
		log.Error(customErr.Error())
		return customErr.Code
	} else {
		errorMsg := err.Error()
		log.Error(errorMsg)

		if strings.Contains(errorMsg, "unexpected argument") {
			return utils.InvalidParameterCombination.Code
		}
		return utils.GenericFailure.Code
	}
}
