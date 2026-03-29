// keyring.go — Linux kernel keyring output backend
// Stores secrets in the user keyring via the keyctl syscall.
// The user keyring (KEY_SPEC_USER_KEYRING) is shared across all processes
// running as the same UID, regardless of session. This allows srvguard to
// run as a separate oneshot service and have the key visible to the Domino
// service that starts afterwards — without the credential file ever appearing
// in Domino's process namespace.
// The consumer reads and immediately removes the key — it never persists.

//go:build linux

package main

import (
    "crypto/rand"
    "crypto/sha256"
    "encoding/hex"
    "encoding/json"
    "fmt"
    "os"
    "path/filepath"
    "strings"
    "syscall"
    "unsafe"
)

// keyctl command constants
const (
    keyctlGetKeyringID = 0
    keyctlUpdate       = 2
    keyctlRevoke       = 3
    keyctlSetperm      = 5
    keyctlSearch       = 10
    keyctlRead         = 11
)

// key permission bits — format: (possessor<<24) | (user<<16) | (group<<8) | other
// bit 0x01=view  0x02=read  0x04=write  0x08=search  0x10=link  0x20=setattr
const (
    keyPermPossessorAll = 0x3f000000 // possessor: full access
    keyPermUserReadable = 0x000b0000 // user (same UID, any session): view+read+search
)

// keyring type
const keyTypeUser = "user"

// keyringBuildSalt is baked into the binary at compile time.
// Must match KEYRING_BUILD_SALT in consumers/cpp/srvguard.cpp.
// Override at build time via SRVGUARD_BUILD_SALT — see compile.sh.
// To generate a fresh value:  od -An -tx1 -N32 /dev/urandom | tr -d ' \n'
var keyringBuildSalt = "162b6cceee498c4e1b9ac4418c4edd50" +
    "3eb5000e0db5c5a0a853a1f5d0f90181"

// keyringSecretFileDefault is the production path for the external secret.
// Override with SRVGUARD_KEYRING_SECRET_FILE for testing (e.g. /tmp/...).
const keyringSecretFileDefault = "/var/lib/srvguard/keyring.secret"

// keyringSecretFile returns the effective path — env var takes precedence.
func keyringSecretFile() string {
    if v := os.Getenv("SRVGUARD_KEYRING_SECRET_FILE"); v != "" {
        return v
    }
    return keyringSecretFileDefault
}

// ensureKeyringSecret creates the external secret file if it does not exist.
// Called before every keyring write so the file is always in place before
// domsrvguard tries to read it.
func ensureKeyringSecret() error {
    path := keyringSecretFile()
    dir  := filepath.Dir(path)

    if err := os.MkdirAll(dir, 0700); err != nil {
        return fmt.Errorf("keyring: creating secret dir: %w", err)
    }

    if _, err := os.Stat(path); os.IsNotExist(err) {
        secret := make([]byte, 32)
        if _, err := rand.Read(secret); err != nil {
            return fmt.Errorf("keyring: generating secret: %w", err)
        }
        if err := os.WriteFile(path, secret, 0400); err != nil {
            return fmt.Errorf("keyring: writing secret file: %w", err)
        }
        logInfo("keyring: created new secret at %s", path)
    }

    return nil
}

// deriveKeyLabel computes SHA256(internal || external || boot_id) and returns
// the first 16 bytes hex-encoded — a 32-character opaque label that changes
// every reboot and cannot be guessed without both secrets.
func deriveKeyLabel() (string, error) {
    internal, err := hex.DecodeString(keyringBuildSalt)
    if err != nil {
        return "", fmt.Errorf("keyring: build salt: %w", err)
    }

    external, err := os.ReadFile(keyringSecretFile())
    if err != nil {
        return "", fmt.Errorf("keyring: reading secret file: %w", err)
    }

    bootIDRaw, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
    if err != nil {
        return "", fmt.Errorf("keyring: reading boot_id: %w", err)
    }
    bootID := strings.TrimSpace(string(bootIDRaw))

    h := sha256.New()
    h.Write(internal)
    h.Write(external)
    h.Write([]byte(bootID))
    sum := h.Sum(nil)

    return hex.EncodeToString(sum[:16]), nil
}

// keyringUser is KEY_SPEC_USER_KEYRING (-4).
// Shared across all processes of the same UID — visible to any service running
// as the same user, regardless of which session wrote the key.
// Must be a var — Go does not allow negative constants in uintptr conversions.
var keyringUser = -4

// keyringWrite serialises the secret data map to JSON and stores it
// in the user keyring under a derived label.
// The label is never passed in from outside — it is always computed from
// the build salt, the external secret file, and the current boot ID.
func keyringWrite(data map[string]string) error {
    if err := ensureKeyringSecret(); err != nil {
        return err
    }

    label, err := deriveKeyLabel()
    if err != nil {
        return fmt.Errorf("keyring: deriving label: %w", err)
    }

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
        uintptr(keyringUser), //nolint:gosec — intentional signed→uintptr for syscall
        0,
    )

    if errno != 0 {
        return fmt.Errorf("keyring: add_key: %w", errno)
    }

    // set permissions so the consumer service (same UID, different session)
    // can search and read the key — default user bits only grant view access
    _, _, errno = syscall.Syscall(
        syscall.SYS_KEYCTL,
        keyctlSetperm,
        r0,
        keyPermPossessorAll|keyPermUserReadable,
    )
    if errno != 0 {
        return fmt.Errorf("keyring: keyctl setperm: %w", errno)
    }

    return nil
}
