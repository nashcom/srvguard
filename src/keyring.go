// keyring.go — Linux kernel keyring output backend
// Stores secrets in the session keyring via the keyctl syscall.
// The consumer reads and immediately removes the key — it never persists.

//go:build linux

package main

import (
  "encoding/json"
  "fmt"
  "syscall"
  "unsafe"
)

// keyctl command constants
const (
  keyctlGetKeyringID = 0
  keyctlUpdate       = 2
  keyctlRevoke       = 3
  keyctlSearch       = 10
  keyctlRead         = 11
)

// keyring type
const keyTypeUser = "user"

// keyringSession is KEY_SPEC_SESSION_KEYRING (-3).
// Must be a var — Go does not allow negative constants in uintptr conversions.
var keyringSession = -3

// keyringWrite serialises the secret data map to JSON and stores it
// in the session keyring under the given label.
func keyringWrite(label string, data map[string]string) error {
  payload, err := json.Marshal(data)
  if err != nil {
    return fmt.Errorf("keyring: marshalling data: %w", err)
  }

  keyType, err := syscall.BytePtrFromString(keyTypeUser)
  if err != nil {
    return err
  }

  keyDesc, err := syscall.BytePtrFromString(label)
  if err != nil {
    return err
  }

  r0, _, errno := syscall.Syscall6(
    syscall.SYS_ADD_KEY,
    uintptr(unsafe.Pointer(keyType)),
    uintptr(unsafe.Pointer(keyDesc)),
    uintptr(unsafe.Pointer(&payload[0])),
    uintptr(len(payload)),
    uintptr(keyringSession), //nolint:gosec — intentional signed→uintptr for syscall
    0,
  )

  if errno != 0 {
    return fmt.Errorf("keyring: add_key: %w", errno)
  }

  _ = r0 // key serial number — consumer uses label to search
  return nil
}
