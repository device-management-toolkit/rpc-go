/*********************************************************************
 * Copyright (c) Intel Corporation 2021
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/
package utils

import (
	"bufio"
	"os"

	"golang.org/x/term"
)

const TestPassword = "test-password"

var PR PasswordReader = new(RealPasswordReader)

type PasswordReader interface {
	ReadPassword() (string, error)
}

type RealPasswordReader struct{}

func (pr *RealPasswordReader) ReadPassword() (string, error) {
	if term.IsTerminal(int(os.Stdin.Fd())) {
		pass, err := term.ReadPassword(int(os.Stdin.Fd()))

		return string(pass), err
	} else {
		reader := bufio.NewReader(os.Stdin)

		pass, err := reader.ReadString('\n')
		if err != nil {
			return "", err
		}

		return pass, nil
	}
}
