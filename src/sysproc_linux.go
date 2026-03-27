//go:build linux

package main

import (
  "os"
  "strings"
  "syscall"
)

func newSysProcAttr() *syscall.SysProcAttr {
  return &syscall.SysProcAttr{Setpgid: true}
}

// envSignal parses a signal name from an environment variable (e.g. "HUP", "TERM").
func envSignal(key string, def syscall.Signal) syscall.Signal {
  v := os.Getenv(key)
  if v == "" {
    return def
  }
  signals := map[string]syscall.Signal{
    "HUP":  syscall.SIGHUP,
    "TERM": syscall.SIGTERM,
    "INT":  syscall.SIGINT,
    "USR1": syscall.SIGUSR1,
    "USR2": syscall.SIGUSR2,
  }
  if s, ok := signals[strings.ToUpper(v)]; ok {
    return s
  }
  return def
}
