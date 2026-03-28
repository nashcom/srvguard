// srvguard — Nash!Com Service Guard
// log.go — Centralised logging with optional JSON output and log levels.
//
// Plain mode (default):
//   2026-03-28T10:00:00Z   INFO     vault token renewed
//
// JSON mode (SRVGUARD_LOG_JSON=true):
//   {"ts":"2026-03-28T10:00:00Z","level":"info","msg":"vault token renewed"}
//
// Log level is controlled by SRVGUARD_LOG_LEVEL (none|error|info|verbose|debug).
// Default is "info".  Setting "none" silences all log output.
//
// showCfg / showInfo always write plain text to stdout regardless of JSON
// mode — they are operator-facing console output, not operational log events.

package main

import (
    "fmt"
    "log"
    "os"
    "strings"
    "time"
)

// -----------------------------------------------------------------------------
// Log level — exact definitions shared across Nash!Com projects
// -----------------------------------------------------------------------------

type LogLevel int

const (
    LOG_NONE LogLevel = iota
    LOG_ERROR
    LOG_INFO
    LOG_VERBOSE
    LOG_DEBUG
)

func (l LogLevel) String() string {
    switch l {
    case LOG_NONE:
        return "NONE"
    case LOG_ERROR:
        return "ERROR"
    case LOG_INFO:
        return "INFO"
    case LOG_VERBOSE:
        return "VERBOSE"
    case LOG_DEBUG:
        return "DEBUG"
    default:
        return "UNKNOWN"
    }
}

func ParseLogLevel(s string) (LogLevel, error) {
    switch strings.ToLower(strings.TrimSpace(s)) {
    case "none":
        return LOG_NONE, nil
    case "error":
        return LOG_ERROR, nil
    case "info":
        return LOG_INFO, nil
    case "verbose":
        return LOG_VERBOSE, nil
    case "debug":
        return LOG_DEBUG, nil
    }
    return LOG_NONE, fmt.Errorf("invalid log level: %s", s)
}

// -----------------------------------------------------------------------------
// Package-level state
// -----------------------------------------------------------------------------

// gLogLevel is the active log level; set from SRVGUARD_LOG_LEVEL at startup.
var gLogLevel = LOG_INFO

// gLogJSON switches all logXxx output to single-line JSON objects.
var gLogJSON = false

// -----------------------------------------------------------------------------
// Core emitters
// -----------------------------------------------------------------------------

// logLine is the single path through which all operational log events flow.
// It is the only place that branches on gLogJSON.
func logLine(level LogLevel, msg string) {
    if gLogLevel == LOG_NONE || level > gLogLevel {
        return
    }
    ts := time.Now().UTC().Format(time.RFC3339)
    if gLogJSON {
        // lowercase level in JSON follows common convention (logfmt, OpenTelemetry)
        log.Printf(`{"ts":%q,"level":%q,"msg":%q}`, ts, strings.ToLower(level.String()), msg)
        return
    }
    log.Printf("%s   %s: %s", ts, level.String(), msg)
}

// logMsg formats a message and emits it at the given level.
func logMsg(level LogLevel, format string, args ...any) {
    if gLogLevel == LOG_NONE || level > gLogLevel {
        return
    }
    logLine(level, fmt.Sprintf(format, args...))
}

// logSpace emits a blank separator line in plain mode only.
// Intentionally a no-op in JSON mode — blank lines break JSON log parsers.
func logSpace() {
    if gLogJSON || gLogLevel == LOG_NONE {
        return
    }
    log.Println("")
}

// -----------------------------------------------------------------------------
// Level-specific shorthands
// -----------------------------------------------------------------------------

func logError(format string, args ...any)   { logMsg(LOG_ERROR, format, args...) }
func logInfo(format string, args ...any)    { logMsg(LOG_INFO, format, args...) }
func logVerbose(format string, args ...any) { logMsg(LOG_VERBOSE, format, args...) }
func logDebug(format string, args ...any)   { logMsg(LOG_DEBUG, format, args...) }

// logFatal logs at ERROR level then exits with status 1.
func logFatal(format string, args ...any) {
    logMsg(LOG_ERROR, format, args...)
    os.Exit(1)
}

// logAlert logs at ERROR level and simultaneously dispatches a mail alert.
// This is the single call site for "operator must be notified immediately".
func logAlert(mcfg *MailConfig, subject, format string, args ...any) {
    msg := fmt.Sprintf(format, args...)
    logMsg(LOG_ERROR, "ALERT: %s", msg)
    SendAlertAsync(mcfg, subject, msg)
}

// -----------------------------------------------------------------------------
// Initialisation
// -----------------------------------------------------------------------------

// initLogging reads SRVGUARD_LOG_LEVEL and SRVGUARD_LOG_JSON from the
// environment and configures the package globals.  It must be called once
// at the very start of main(), before any log output is produced.
// It also suppresses the standard log package's own timestamp prefix since
// logLine formats its own.
func initLogging() {
    log.SetFlags(0)
    log.SetPrefix("")

    if v := os.Getenv("SRVGUARD_LOG_LEVEL"); v != "" {
        level, err := ParseLogLevel(v)
        if err != nil {
            fmt.Fprintf(os.Stderr, "srvguard: %v\n", err)
        } else {
            gLogLevel = level
        }
    }

    gLogJSON = os.Getenv("SRVGUARD_LOG_JSON") == "true"
}

// -----------------------------------------------------------------------------
// Console output — bypasses JSON mode intentionally
// -----------------------------------------------------------------------------

// showInfo writes a human-readable key/value line to stdout.
// Used for banners and operator-facing status output; never JSON.
func showInfo(description, currentValue any) {
    fmt.Printf("%-20v  %v\n", description, currentValue)
}

// showCfg writes a single config variable row to stdout.
// Used by --config; always plain text so the operator can read it directly.
func showCfg(variableName, description, defaultValue, currentValue any) {
    fmt.Printf("%-34v  %-34v  %-30v  %v\n",
        variableName, description, defaultValue, currentValue)
}
