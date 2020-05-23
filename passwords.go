package main

import (
	"bytes"
	"fmt"
	"syscall"

	"golang.org/x/crypto/ssh/terminal"
)

func ReadPassword(prompt string) ([]byte, error) {
	fmt.Print(prompt)
	password, err := terminal.ReadPassword(syscall.Stdin)
	if err != nil {
		return nil, err
	}
	fmt.Println("")

	return password, nil
}

func ReadPasswordWithConfirmation(prompt, confirmationPrompt string) ([]byte, error) {
	fmt.Print(prompt)
	password1, err := terminal.ReadPassword(syscall.Stdin)
	if err != nil {
		return nil, err
	}
	fmt.Println("")

	fmt.Print(confirmationPrompt)
	password2, err := terminal.ReadPassword(syscall.Stdin)
	if err != nil {
		return nil, err
	}
	fmt.Println("")

	if !bytes.Equal(password1, password2) {
		return nil, fmt.Errorf("password mismatch")
	}

	return password1, nil
}

func ReadPrivateKeyPassword(name string) ([]byte, error) {
	prompt := fmt.Sprintf("private key password (%s): ", name)

	return ReadPassword(prompt)
}

func ReadPrivateKeyPasswordForCreation(name string) ([]byte, error) {
	// Stay compatible with OpenSSL
	const minLen = 4
	const maxLen = 1023

	prompt := fmt.Sprintf("private key password (%s): ", name)

	password, err := ReadPasswordWithConfirmation(prompt, "confirmation: ")
	if err != nil {
		return nil, err
	}

	if len(password) < minLen {
		return nil, fmt.Errorf(
			"password too short (min: %d bytes)", minLen)
	}

	if len(password) > maxLen {
		return nil, fmt.Errorf(
			"password too long (max: %d bytes)", maxLen)
	}

	return password, nil
}
