//go:build windows

package main

import (
    "os"
    "strings"
    "syscall"
)

func newSysProcAttr() *syscall.SysProcAttr {
    return &syscall.SysProcAttr{}
}

// envSignal parses a signal name from an environment variable.
func envSignal(key string, def syscall.Signal) syscall.Signal {
    v := os.Getenv(key)
    if v == "" {
        return def
    }
    signals := map[string]syscall.Signal{
        "HUP":  syscall.SIGHUP,
        "TERM": syscall.SIGTERM,
        "INT":  syscall.SIGINT,
    }
    if s, ok := signals[strings.ToUpper(v)]; ok {
        return s
    }
    return def
}
