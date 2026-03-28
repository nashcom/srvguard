// srvguard — Nash!Com Service Guard
// mail.go — srvguard-mail: SMTP alert notification module.
//
// Delivers plain-text alert emails via a configured relay host or by
// discovering the MX record for the recipient domain.  STARTTLS is
// supported in three modes:
//
//   required      — fail if the server does not offer STARTTLS
//   opportunistic — upgrade if offered, continue plain if not (default)
//   off           — never attempt STARTTLS (localhost relay / debugging)
//
// Auth is optional; when Username is set, PLAIN auth is used after the
// TLS handshake.  No external dependencies — only the Go standard library.

package main

import (
    "crypto/rand"
    "crypto/tls"
    "encoding/hex"
    "fmt"
    "net"
    "net/smtp"
    "os"
    "strings"
    "time"
)

// MailConfig holds SMTP notification settings.
// Populated from environment variables via loadConfig().
type MailConfig struct {
    From         string // envelope + header From address; defaults to srvguard@<hostname>
    To           string // recipient(s), comma-separated
    RelayHost    string // "host" or "host:port"; empty = MX discovery on port 25
    RelayPort    string // port when RelayHost has none; default "587" for relay, "25" for MX
    Username     string // SMTP AUTH username (optional)
    Password     string // SMTP AUTH password (optional)
    STARTTLSMode string // "required" | "opportunistic" (default) | "off"
    SkipVerify   bool   // skip TLS certificate verification (lab/test use only)
}

// Enabled returns true when there is at least one recipient configured.
func (m *MailConfig) Enabled() bool {
    return m != nil && strings.TrimSpace(m.To) != ""
}

// SendAlert composes and delivers a plain-text alert email.
// Subject is prefixed with "[srvguard] " automatically.
// Returns nil without attempting delivery when MailConfig is not enabled.
func SendAlert(mcfg *MailConfig, subject, body string) error {
    if !mcfg.Enabled() {
        return nil
    }

    hostport, err := mcfg.resolveHostPort()
    if err != nil {
        return fmt.Errorf("mail: resolve host: %w", err)
    }

    from := mcfg.From
    if from == "" {
        hostname, _ := os.Hostname()
        from = "srvguard: " + hostname + " <srvguard@" + hostname + ">"
    }

    msg := buildMessage(from, mcfg.To, "[srvguard] "+subject, body)

    if err := mcfg.deliver(hostport, from, msg); err != nil {
        return fmt.Errorf("mail: deliver to %s: %w", hostport, err)
    }
    return nil
}

// SendAlertAsync delivers the alert in a background goroutine with a 30-second
// overall timeout.  Delivery errors are logged; the caller is never blocked.
func SendAlertAsync(mcfg *MailConfig, subject, body string) {
    if !mcfg.Enabled() {
        return
    }
    go func() {
        done := make(chan error, 1)
        go func() { done <- SendAlert(mcfg, subject, body) }()
        select {
        case err := <-done:
            if err != nil {
                logError("mail: %v", err)
            }
        case <-time.After(30 * time.Second):
            logError("mail: delivery timed out after 30s")
        }
    }()
}

// -----------------------------------------------------------------------------
// Internal helpers
// -----------------------------------------------------------------------------

// resolveHostPort returns "host:port" for SMTP delivery.
//
// Priority:
//  1. RelayHost with explicit port  (used verbatim)
//  2. RelayHost without port        (RelayPort appended; default 587)
//  3. No RelayHost                  (MX lookup, port 25)
func (m *MailConfig) resolveHostPort() (string, error) {
    if m.RelayHost != "" {
        if strings.Contains(m.RelayHost, ":") {
            return m.RelayHost, nil
        }
        port := m.RelayPort
        if port == "" {
            port = "587"
        }
        return m.RelayHost + ":" + port, nil
    }

    // MX discovery — use first recipient for the domain lookup
    firstRcpt := strings.TrimSpace(strings.SplitN(m.To, ",", 2)[0])
    domain, err := recipientDomain(firstRcpt)
    if err != nil {
        return "", err
    }
    mxs, err := net.LookupMX(domain)
    if err != nil {
        return "", fmt.Errorf("MX lookup for %s: %w", domain, err)
    }
    if len(mxs) == 0 {
        return "", fmt.Errorf("no MX records found for %s", domain)
    }
    // net.LookupMX returns records sorted by preference (lowest = highest priority)
    mx := strings.TrimSuffix(mxs[0].Host, ".")
    port := m.RelayPort
    if port == "" {
        port = "25"
    }
    return mx + ":" + port, nil
}

// deliver opens an SMTP connection, optionally upgrades to TLS, optionally
// authenticates, and transmits the pre-built message bytes.
func (m *MailConfig) deliver(hostport, from string, msg []byte) error {
    host, _, err := net.SplitHostPort(hostport)
    if err != nil {
        return fmt.Errorf("invalid hostport %q: %w", hostport, err)
    }

    c, err := smtp.Dial(hostport)
    if err != nil {
        return fmt.Errorf("dial: %w", err)
    }
    defer c.Close()

    if err = c.Hello(localHostname()); err != nil {
        return fmt.Errorf("EHLO: %w", err)
    }

    // ── STARTTLS ─────────────────────────────────────────────────────────────
    mode := strings.ToLower(strings.TrimSpace(m.STARTTLSMode))
    if mode == "" {
        mode = "opportunistic"
    }

    if mode != "off" {
        offered, _ := c.Extension("STARTTLS")
        switch {
        case offered:
            tlsCfg := &tls.Config{
                ServerName:         host,
                InsecureSkipVerify: m.SkipVerify, //nolint:gosec // controlled by operator config
            }
            if err = c.StartTLS(tlsCfg); err != nil {
                if mode == "required" {
                    return fmt.Errorf("STARTTLS required but handshake failed: %w", err)
                }
                // opportunistic: log and continue in plain
                logError("mail: STARTTLS offered but handshake failed, continuing plain: %v", err)
            }
        case mode == "required":
            return fmt.Errorf("STARTTLS required but not offered by %s", host)
        }
    }

    // ── AUTH (optional) ──────────────────────────────────────────────────────
    if m.Username != "" {
        auth := smtp.PlainAuth("", m.Username, m.Password, host)
        if err = c.Auth(auth); err != nil {
            return fmt.Errorf("AUTH: %w", err)
        }
    }

    // ── Envelope ─────────────────────────────────────────────────────────────
    if err = c.Mail(bareAddr(from)); err != nil {
        return fmt.Errorf("MAIL FROM: %w", err)
    }
    for _, rcpt := range strings.Split(m.To, ",") {
        rcpt = strings.TrimSpace(rcpt)
        if rcpt == "" {
            continue
        }
        if err = c.Rcpt(rcpt); err != nil {
            return fmt.Errorf("RCPT TO <%s>: %w", rcpt, err)
        }
    }

    // ── Data ─────────────────────────────────────────────────────────────────
    w, err := c.Data()
    if err != nil {
        return fmt.Errorf("DATA: %w", err)
    }
    if _, err = w.Write(msg); err != nil {
        _ = w.Close()
        return fmt.Errorf("write body: %w", err)
    }
    if err = w.Close(); err != nil {
        return fmt.Errorf("end DATA: %w", err)
    }

    return c.Quit()
}

// SendConfigMail sends the full effective configuration as a mail message.
// When to is non-empty it overrides mcfg.To for this delivery only, which
// allows ad-hoc recipients (e.g. from --test-mail <addr>) without changing
// the persistent alert destination.
// The call is synchronous so the caller can report pass/fail immediately.
func SendConfigMail(mcfg *MailConfig, to string, vars []varDef) error {
    // build a throwaway config copy so we never mutate the caller's struct
    cfg := *mcfg
    if to != "" {
        cfg.To = to
    }
    if !cfg.Enabled() {
        return fmt.Errorf("no recipient: set SRVGUARD_MAIL_TO or pass an address to --test-mail")
    }

    hostname, _ := os.Hostname()
    var sb strings.Builder
    fmt.Fprintf(&sb, "srvguard configuration report from %s\n\n", hostname)
    fmt.Fprintf(&sb, "%-34s  %s\n", "Variable", "Effective Value")
    fmt.Fprintf(&sb, "%s\n", strings.Repeat("-", 72))
    for _, v := range vars {
        fmt.Fprintf(&sb, "%-34s  %s\n", v.name, v.effective())
    }

    return SendAlert(&cfg, "configuration report", sb.String())
}

// bareAddr extracts the plain email address from an RFC 5322 address field.
// "SrvGuard <srvguard@host>" → "srvguard@host"
// "srvguard@host"            → "srvguard@host"
func bareAddr(addr string) string {
    if lt := strings.Index(addr, "<"); lt >= 0 {
        addr = addr[lt+1:]
        if gt := strings.Index(addr, ">"); gt >= 0 {
            addr = addr[:gt]
        }
    }
    return strings.TrimSpace(addr)
}

// generateMessageID returns a globally unique Message-ID string in the
// form <timestamp.randombytes@hostname>, e.g.
//   <1743163489123456789.a3f8b2c1d4e5f6a7@nsh-t14>
// The host component comes from the bare From address so it stays
// consistent whether From was set explicitly or defaulted to os.Hostname().
func generateMessageID(from string) string {
    b := make([]byte, 8)
    if _, err := rand.Read(b); err != nil {
        _ = err
    }
    host := "localhost"
    if at := strings.LastIndex(bareAddr(from), "@"); at >= 0 {
        host = bareAddr(from)[at+1:]
    }
    return fmt.Sprintf("<%d.%s@%s>", time.Now().UnixNano(), hex.EncodeToString(b), host)
}

// buildHeaders returns the RFC 2822 header block (including the blank
// separator line) for a plain-text alert message.
// Add fields here when needed — Reply-To, etc.
func buildHeaders(from, to, subject string) string {
    date := time.Now().UTC().Format("Mon, 02 Jan 2006 15:04:05 +0000")
    fields := []string{
        "From: " + from,
        "To: " + to,
        "Subject: " + subject,
        "Date: " + date,
        "Message-ID: " + generateMessageID(from),
        "MIME-Version: 1.0",
        "Content-Type: text/plain; charset=utf-8",
        "Importance: high",   // RFC 2156 — Notes priority flag in view
        "X-Priority: 1",      // de facto standard (Outlook, Traveler)
        "X-Mailer: srvguard-mail",
        "", // blank line separates headers from body (RFC 2822 §2.1)
    }
    return strings.Join(fields, "\r\n")
}

// buildMessage composes a complete RFC 2822 message with CRLF line endings.
func buildMessage(from, to, subject, body string) []byte {
    // normalise body line endings to CRLF before appending
    body = strings.ReplaceAll(body, "\r\n", "\n")
    body = strings.ReplaceAll(body, "\n", "\r\n")
    return []byte(buildHeaders(from, to, subject) + "\r\n" + body)
}

// recipientDomain extracts the domain part of an email address.
// Handles both bare addresses (user@domain) and RFC 2822 display-name form
// ("Display Name <user@domain>").
func recipientDomain(addr string) (string, error) {
    addr = strings.TrimSpace(addr)
    if i := strings.Index(addr, "<"); i != -1 {
        addr = strings.TrimSuffix(addr[i+1:], ">")
    }
    parts := strings.SplitN(addr, "@", 2)
    if len(parts) != 2 || parts[1] == "" {
        return "", fmt.Errorf("cannot parse domain from address %q", addr)
    }
    return parts[1], nil
}

// localHostname returns the system hostname for use in EHLO.
// Falls back to "localhost" if the OS call fails.
func localHostname() string {
    h, err := os.Hostname()
    if err != nil {
        return "localhost"
    }
    return h
}
