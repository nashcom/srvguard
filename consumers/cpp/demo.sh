#!/bin/bash
# srvguard — keyring consumer demo
#
# Full chain:
#   systemd (LoadCredentialEncrypted=)
#     → $CREDENTIALS_DIRECTORY/key_password      (tmpfs, service-scoped)
#       → srvguard (AUTH_METHOD=local)
#         → kernel keyring {"key_password":"..."}
#           → example binary
#               SrvGuardKeyringRead("srvguard", "key_password", ...)
#               key revoked, memory zeroed
#
# Requirements:
#   - systemd v250+  with credential support
#   - /var/lib/systemd/credential.secret  (created automatically if missing)
#   - g++, make
#   - srvguard binary  (export SRVGUARD_BIN= to override)
#
# Usage:
#   ./demo.sh
#   ./demo.sh --clean
#   SRVGUARD_BIN=/path/to/srvguard ./demo.sh

set -euo pipefail

UNIT_NAME="srvguard-keyring-demo"
CRED_NAME="key_password"          # must match SrvGuardKeyringRead field in example.cpp
CRED_FILE="/tmp/${CRED_NAME}"
SRVGUARD_BIN="${SRVGUARD_BIN:-/bin/srvguard}"
EXAMPLE_BIN="$(cd "$(dirname "$0")" && pwd)/example"

log()  { echo "  $*"; }
info() { echo; echo "── $* ──"; }
die()  { echo "ERROR: $*" >&2; exit 1; }

# ── Clean ─────────────────────────────────────────────────────────────────────

if [[ "${1:-}" == "--clean" ]]; then
    systemctl is-active --quiet "${UNIT_NAME}.service" 2>/dev/null && \
        systemctl stop "${UNIT_NAME}.service" && log "stopped ${UNIT_NAME}.service"
    systemctl reset-failed "${UNIT_NAME}.service" 2>/dev/null || true
    rm -f "$CRED_FILE"
    log "removed $CRED_FILE"
    echo; echo "Clean."; exit 0
fi

# ── Prerequisites ─────────────────────────────────────────────────────────────

info "Checking prerequisites"

command -v g++           &>/dev/null || die "g++ not found — install build-essential"
command -v make          &>/dev/null || die "make not found — install build-essential"
command -v systemd-creds &>/dev/null || die "systemd-creds not found (need systemd v250+)"
command -v systemd-run   &>/dev/null || die "systemd-run not found"
[[ -x "$SRVGUARD_BIN" ]]            || die "$SRVGUARD_BIN not found — export SRVGUARD_BIN="

SYSTEMD_VER=$(systemctl --version | awk 'NR==1{print $2}')
[[ "$SYSTEMD_VER" -ge 250 ]]        || die "systemd v250+ required (have $SYSTEMD_VER)"
log "systemd version: $SYSTEMD_VER"

# Verify credential support and report which backend is active
if systemd-creds has-tpm2 &>/dev/null; then
    log "credential backend: TPM2 (hardware-bound)"
elif [[ -f /var/lib/systemd/credential.secret ]]; then
    log "credential backend: credential.secret (machine-specific, no TPM2)"
else
    log "no credential backend found — running systemd-creds setup ..."
    systemd-creds setup
    log "credential backend: credential.secret (created)"
fi

# ── Build example binary ──────────────────────────────────────────────────────

info "Building example consumer"

make -C "$(dirname "$0")" example
log "built: $EXAMPLE_BIN"

# ── Encrypt test secret ───────────────────────────────────────────────────────

info "Encrypting test secret"

TEST_SECRET="demo-password-$(date +%s)"
log "secret value:  $TEST_SECRET"
log "credential:    $CRED_NAME"
log "encrypted to:  $CRED_FILE"

echo -n "$TEST_SECRET" | \
    systemd-creds encrypt - "$CRED_FILE" || \
    die "systemd-creds encrypt failed — this machine may not support credential encryption."

# Verify round-trip
VERIFY=$(systemd-creds decrypt "$CRED_FILE" -)
[[ "$VERIFY" == "$TEST_SECRET" ]] || die "credential verify failed"
log "decrypt verified OK"
unset TEST_SECRET VERIFY

# ── Launch transient service ──────────────────────────────────────────────────

info "Launching transient service: ${UNIT_NAME}.service"

echo
echo "  Chain:"
echo "    systemd LoadCredentialEncrypted= → \$CREDENTIALS_DIRECTORY/$CRED_NAME"
echo "    srvguard (local mode)            → kernel keyring {\"$CRED_NAME\":\"...\"}"
echo "    example binary                   → SrvGuardKeyringRead → revoke → zero"
echo

systemctl is-active --quiet "${UNIT_NAME}.service" 2>/dev/null && \
    systemctl stop "${UNIT_NAME}.service"
systemctl reset-failed "${UNIT_NAME}.service" 2>/dev/null || true

systemd-run \
    --unit="${UNIT_NAME}" \
    --service-type=oneshot \
    --property="LoadCredentialEncrypted=${CRED_NAME}:${CRED_FILE}" \
    --setenv=SRVGUARD_AUTH_METHOD=local \
    --setenv=SRVGUARD_SYSTEMD_CRED="${CRED_NAME}" \
    --setenv=SRVGUARD_OUTPUT_MODE=keyring \
    --setenv=SRVGUARD_KEYRING_LABEL=srvguard \
    "$SRVGUARD_BIN" -- "$EXAMPLE_BIN"

# ── Result ────────────────────────────────────────────────────────────────────

info "Result"
sleep 1
journalctl -u "${UNIT_NAME}.service" --no-pager -o cat | grep -v "^$"

echo
echo "  Next step: demo-transient.sh — same flow with Vault in the middle"
