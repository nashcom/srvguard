// keyring_stub.go — stub for non-Linux platforms

//go:build !linux

package main

import "fmt"

func ensureKeyringSecret() error { return nil }

func deriveKeyLabel() (string, error) { return "", fmt.Errorf("keyring not supported on this platform") }

func keyringWrite(data map[string]string) error {
    return fmt.Errorf("kernel keyring is only supported on Linux")
}
