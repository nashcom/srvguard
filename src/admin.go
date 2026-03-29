// admin.go — srvguard admin commands: --bootstrap and --rotate
//
// Manages the systemd encrypted credential file used by
// SRVGUARD_AUTH_METHOD=systemd.  Both commands require systemd-creds(1)
// from systemd v250+.
//
// --bootstrap  Encrypt a new credential value and write the .cred file for the
//              first time (or replace it after explicit confirmation).
//
// --rotate     Replace the credential file atomically using a two-phase commit
//              with in-memory rollback.
//
// Rollback design
// ───────────────
// Both commands hold the new encrypted bytes in a temp file until the atomic
// rename succeeds.  --rotate additionally holds the *old* encrypted bytes in
// memory from the moment it reads the existing file.  If the rename fails, it
// writes those bytes back — no re-prompt required.  This is cost-free: reading
// the current credential is an inherent first step of any rotation, so both
// old and new state are already in memory when the commit is attempted.

//go:build linux

package main

import (
    "bufio"
    "bytes"
    "fmt"
    "io"
    "os"
    "os/exec"
    "strings"
)

// credFileDefault is the production path for the systemd credential file.
// Override with SRVGUARD_CRED_FILE or pass an explicit path on the command line.
const credFileDefault = "/etc/srvguard/vault-token.cred"

// credFilePath resolves the effective credential file path.
// Priority: explicit command-line arg → SRVGUARD_CRED_FILE env var → default.
func credFilePath(arg string) string {
    if arg != "" {
        return arg
    }
    if v := os.Getenv("SRVGUARD_CRED_FILE"); v != "" {
        return v
    }
    return credFileDefault
}

// readSecret prints prompt to stderr, suppresses terminal echo, reads one line
// from stdin, then restores echo.  If stdin is not a terminal (pipe / redirect)
// the read proceeds silently and stty errors are ignored.
// Returns the trimmed value as a byte slice so the caller can zero it after use.
func readSecret(prompt string) ([]byte, error) {
    fmt.Fprint(os.Stderr, prompt)

    // disable echo — stty operates on whatever terminal is attached to its own
    // stdin, so we pass os.Stdin through.  Errors are intentionally ignored:
    // if stdin is a pipe, stty fails harmlessly and the read continues.
    sttyOff := exec.Command("stty", "-echo")
    sttyOff.Stdin  = os.Stdin
    sttyOff.Stderr = io.Discard
    _ = sttyOff.Run()

    defer func() {
        sttyOn := exec.Command("stty", "echo")
        sttyOn.Stdin  = os.Stdin
        sttyOn.Stderr = io.Discard
        _ = sttyOn.Run()
        fmt.Fprintln(os.Stderr) // newline after the hidden input
    }()

    reader := bufio.NewReader(os.Stdin)
    line, err := reader.ReadBytes('\n')
    if err != nil && err != io.EOF {
        return nil, fmt.Errorf("reading secret: %w", err)
    }

    // strip trailing CR/LF
    for len(line) > 0 && (line[len(line)-1] == '\n' || line[len(line)-1] == '\r') {
        line = line[:len(line)-1]
    }
    if len(line) == 0 {
        return nil, fmt.Errorf("empty value — aborted")
    }
    return line, nil
}

// zeroBytes overwrites b with zeros.  Called via defer to clear secret material.
func zeroBytes(b []byte) {
    for i := range b {
        b[i] = 0
    }
}

// encryptCred runs systemd-creds encrypt, piping value to stdin and writing
// the resulting encrypted credential to outPath.
func encryptCred(value []byte, outPath string) error {
    cmd := exec.Command("systemd-creds", "encrypt", "-", outPath)
    cmd.Stdin  = bytes.NewReader(value)
    cmd.Stdout = os.Stdout
    cmd.Stderr = os.Stderr
    if err := cmd.Run(); err != nil {
        return fmt.Errorf("systemd-creds encrypt: %w", err)
    }
    return nil
}

// verifyCred runs systemd-creds decrypt on inPath as a round-trip check.
// Returns an error if the file cannot be decrypted — used to confirm the
// existing credential is healthy before rotating it.
func verifyCred(inPath string) error {
    out, err := exec.Command("systemd-creds", "decrypt", inPath, "-").Output()
    if err != nil {
        return fmt.Errorf("systemd-creds decrypt: %w", err)
    }
    if len(out) == 0 {
        return fmt.Errorf("decrypted credential is empty")
    }
    return nil
}

// ─────────────────────────────────────────────────────────────────────────────
// Bootstrap
// ─────────────────────────────────────────────────────────────────────────────

// runBootstrap implements srvguard --bootstrap [path].
//
// Encrypts a new credential value and writes it to the .cred file.
// Prompts for confirmation before overwriting an existing file.
//
// Usage:
//   srvguard --bootstrap
//   srvguard --bootstrap /etc/srvguard/vault-token.cred
func runBootstrap(argPath string) error {
    credFile := credFilePath(argPath)

    // warn before overwriting an existing file
    if _, err := os.Stat(credFile); err == nil {
        fmt.Fprintf(os.Stderr, "srvguard: %s already exists — overwrite? [y/N] ", credFile)
        var answer string
        fmt.Scanln(&answer) //nolint:errcheck
        if strings.ToLower(strings.TrimSpace(answer)) != "y" {
            fmt.Fprintln(os.Stderr, "aborted")
            return nil
        }
    }

    value, err := readSecret("New credential value (input hidden): ")
    if err != nil {
        return err
    }
    defer zeroBytes(value)

    tmp := credFile + ".tmp"

    if err := encryptCred(value, tmp); err != nil {
        _ = os.Remove(tmp)
        return err
    }

    if err := os.Rename(tmp, credFile); err != nil {
        _ = os.Remove(tmp)
        return fmt.Errorf("writing credential file: %w", err)
    }

    fmt.Printf("bootstrap: credential written to %s\n", credFile)
    fmt.Printf("bootstrap: configure your service unit:\n")
    fmt.Printf("bootstrap:   LoadCredentialEncrypted=vault-token:%s\n", credFile)
    return nil
}

// ─────────────────────────────────────────────────────────────────────────────
// Rotate
// ─────────────────────────────────────────────────────────────────────────────

// runRotate implements srvguard --rotate [path].
//
// Replaces the credential file atomically with a two-phase commit.
// The old encrypted bytes are held in memory from the first read so that
// a rollback requires no re-prompt and no re-encryption.
//
//   Phase 1 — read current .cred file bytes into memory (rollback copy)
//   Phase 2 — verify we can decrypt the current file before touching it
//   Phase 3 — prompt for new value, encrypt to .cred.new
//   Commit  — atomic rename .cred.new → .cred
//   Rollback — if rename fails, restore old bytes from memory
//
// Usage:
//   srvguard --rotate
//   srvguard --rotate /etc/srvguard/vault-token.cred
func runRotate(argPath string) error {
    credFile := credFilePath(argPath)

    // Phase 1: read old encrypted bytes — this is our rollback copy.
    // We need to read the file before any write anyway, so holding the bytes
    // in memory costs nothing extra.
    oldEncBytes, err := os.ReadFile(credFile)
    if err != nil {
        return fmt.Errorf("reading current credential %s: %w\n"+
            "  (run srvguard --bootstrap to create a new credential file)", credFile, err)
    }

    // Phase 2: verify the current file is healthy before we replace it.
    // If this machine cannot decrypt it, rotating it would not help.
    if err := verifyCred(credFile); err != nil {
        return fmt.Errorf("current credential cannot be decrypted — will not replace: %w", err)
    }

    // Phase 3: get new value and encrypt to a temp file.
    value, err := readSecret("New credential value (input hidden): ")
    if err != nil {
        return err
    }
    defer zeroBytes(value)

    tmp := credFile + ".new"

    if err := encryptCred(value, tmp); err != nil {
        _ = os.Remove(tmp)
        return err
    }

    // Commit: atomic rename — succeeds as long as both paths are on the same
    // filesystem (they always are here since .new is next to .cred).
    if err := os.Rename(tmp, credFile); err != nil {
        // Rollback: restore old encrypted bytes from memory.
        // The service is still running on the old credential, so this is safe.
        _ = os.Remove(tmp)
        if rbErr := os.WriteFile(credFile, oldEncBytes, 0600); rbErr != nil {
            return fmt.Errorf(
                "rename failed (%w) and rollback also failed (%v) — "+
                    "manual recovery required: restore %s from backup",
                err, rbErr, credFile)
        }
        return fmt.Errorf("rotate failed — old credential restored (rollback OK): %w", err)
    }

    // zero the rollback copy now that we no longer need it
    zeroBytes(oldEncBytes)

    fmt.Printf("rotate: credential updated at %s\n", credFile)
    fmt.Printf("rotate: restart the service to apply the new credential:\n")
    fmt.Printf("rotate:   systemctl restart <your-srvguard-service>\n")
    return nil
}
