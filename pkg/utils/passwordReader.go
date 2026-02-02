/*********************************************************************
 * Copyright (c) Intel Corporation 2021
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/
package utils

import (
	"bufio"
	"fmt"
	"os"

	"golang.org/x/term"
)

const TestPassword = "test-password"

var PR PasswordReader = new(RealPasswordReader)

type PasswordReader interface {
	ReadPassword() (string, error)
	ReadPasswordWithConfirmation(prompt, confirmPrompt string) (string, error)
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

func (pr *RealPasswordReader) ReadPasswordWithConfirmation(prompt, confirmPrompt string) (string, error) {
	fmt.Print(prompt)

	pw1, err := pr.ReadPassword()
	if err != nil {
		return "", err
	}

	fmt.Println()

	fmt.Print(confirmPrompt)

	pw2, err := pr.ReadPassword()
	if err != nil {
		return "", err
	}

	fmt.Println()

	if pw1 != pw2 {
		return "", PasswordsDoNotMatch
	}

	return pw1, nil
}
