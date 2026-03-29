// admin_stub.go — stub implementations for non-Linux platforms
//
// --bootstrap and --rotate require systemd-creds(1), which is Linux-only.

//go:build !linux

package main

import "fmt"

func runBootstrap(_ string) error {
    return fmt.Errorf("--bootstrap requires Linux (systemd-creds is not available on this platform)")
}

func runRotate(_ string) error {
    return fmt.Errorf("--rotate requires Linux (systemd-creds is not available on this platform)")
}
