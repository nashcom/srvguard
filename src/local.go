// srvguard — Nash!Com Service Guard
// local.go — local passthrough mode (SRVGUARD_AUTH_METHOD=local).
//
// Reads a credential delivered by systemd into $CREDENTIALS_DIRECTORY and
// passes it directly to the configured output backend (keyring or files)
// without contacting Vault.  The child process is then launched and supervised
// exactly as in the Vault-backed modes.
//
// Intended for demos and integration testing — the full systemd + srvguard
// delivery path is exercised without requiring a Vault instance.
//
// Flow:
//   systemd (LoadCredentialEncrypted=)
//     → $CREDENTIALS_DIRECTORY/<cred>   (plaintext, tmpfs, service-scoped)
//       → srvguard (local mode)
//         → keyring / files
//           → child process

package main

import (
    "fmt"
    "os"
    "path/filepath"
    "strings"
)

// runLocal reads the named credential from $CREDENTIALS_DIRECTORY and writes
// it to the configured output backend.  The credential name becomes the field
// name in the keyring JSON payload so the C++ consumer calls:
//
//   SrvGuardKeyringRead("srvguard", "<cred-name>", buf, sizeof(buf))
func runLocal(cfg *Config) error {
    credDir := os.Getenv("CREDENTIALS_DIRECTORY")
    if credDir == "" {
        return fmt.Errorf("CREDENTIALS_DIRECTORY not set — " +
            "add LoadCredential= or LoadCredentialEncrypted= to the unit")
    }

    credPath := filepath.Join(credDir, cfg.SystemdCred)
    raw, err := os.ReadFile(credPath)
    if err != nil {
        return fmt.Errorf("reading credential %q: %w", credPath, err)
    }

    // trim trailing newline — common when the credential was written with echo
    value := strings.TrimRight(string(raw), "\r\n")
    if value == "" {
        return fmt.Errorf("credential %q is empty", cfg.SystemdCred)
    }

    // the credential name becomes the JSON field name so the consumer
    // does not need to know whether it is talking to local or Vault mode
    data := map[string]string{
        cfg.SystemdCred: value,
    }

    logInfo("local: loaded credential %q (%d bytes) from %s",
        cfg.SystemdCred, len(value), credDir)

    if err := writeSecrets(cfg, data); err != nil {
        return fmt.Errorf("writing secrets: %w", err)
    }

    return nil
}
