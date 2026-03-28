// systemd_stub.go — stub for non-Linux platforms
//
// systemd credential auth is Linux-specific.  $CREDENTIALS_DIRECTORY and the
// LoadCredential= directive do not exist on other platforms.

//go:build !linux

package main

import "fmt"

func (c *vaultClient) loginSystemd(cfg *Config) error {
    return fmt.Errorf(
        "systemd credential auth (SRVGUARD_AUTH_METHOD=systemd) requires Linux",
    )
}
