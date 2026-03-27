// keyring_stub.go — stub for non-Linux platforms

//go:build !linux

package main

import "fmt"

func keyringWrite(label string, data map[string]string) error {
  return fmt.Errorf("kernel keyring is only supported on Linux")
}
