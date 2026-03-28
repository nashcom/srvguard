// systemd.go — systemd credential auth source (Linux only)
//
// When SRVGUARD_AUTH_METHOD=systemd, srvguard reads a pre-issued Vault token
// from a systemd credential injected at service startup.  No login endpoint
// is called — the token itself is the credential.
//
// systemd delivers encrypted credentials to services via LoadCredential= /
// LoadCredentialEncrypted= directives in the unit file.  The runtime path is
// set in $CREDENTIALS_DIRECTORY by the service manager; srvguard reads the
// named credential from that directory.
//
// Example unit snippet:
//   [Service]
//   LoadCredentialEncrypted=vault-token:/etc/srvguard/vault-token.cred
//   Environment=SRVGUARD_AUTH_METHOD=systemd
//
// The credential is decrypted by systemd using TPM2 or a machine-derived key
// before the service starts — no custom crypto in srvguard is required for
// the VM/bare-metal path.

//go:build linux

package main

import (
    "fmt"
    "os"
    "path/filepath"
)

// loginSystemd authenticates by reading a Vault token from a systemd
// credential.  $CREDENTIALS_DIRECTORY must be set by the service manager.
// The credential name is cfg.SystemdCred (default "vault-token").
func (c *vaultClient) loginSystemd(cfg *Config) error {
    credsDir := os.Getenv("CREDENTIALS_DIRECTORY")
    if credsDir == "" {
        return fmt.Errorf(
            "CREDENTIALS_DIRECTORY is not set — srvguard must run as a systemd service with LoadCredential= configured",
        )
    }

    credPath := filepath.Join(credsDir, cfg.SystemdCred)
    token, err := readFile(credPath)
    if err != nil {
        return fmt.Errorf("reading systemd credential %q: %w", credPath, err)
    }
    if token == "" {
        return fmt.Errorf("systemd credential %q is empty", credPath)
    }

    c.token = token
    return nil
}
