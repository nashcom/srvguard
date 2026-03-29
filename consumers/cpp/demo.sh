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
#
# Usage:
#   ./demo.sh
#   ./demo.sh --clean

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
UNIT_NAME="srvguard-keyring-demo"
CRED_NAME="key_password"          # must match SrvGuardKeyringRead field in example.cpp
CRED_FILE="/tmp/${CRED_NAME}"
EXAMPLE_BIN="${SCRIPT_DIR}/example"

# Demo uses /tmp for the keyring secret — no system dependencies, no sudo.
# Production default is /var/lib/srvguard/keyring.secret (created by srvguard).
KEYRING_SECRET_FILE="/tmp/srvguard-keyring.secret"

log()  { echo "  $*"; }
info() { echo; echo "── $* ──"; }
die()  { echo "ERROR: $*" >&2; exit 1; }

# Locate srvguard: project bin/ → system /bin → PATH
if [ -x "${SCRIPT_DIR}/../../bin/srvguard" ]; then
    SRVGUARD_BIN="$(realpath "${SCRIPT_DIR}/../../bin/srvguard")"
elif [ -x "/bin/srvguard" ]; then
    SRVGUARD_BIN="$(realpath "/bin/srvguard")"
elif command -v srvguard &>/dev/null; then
    SRVGUARD_BIN="$(realpath "$(command -v srvguard)")"
else
    die "srvguard binary not found — run ./compile.sh -docker from the project root"
fi

# ── Clean ─────────────────────────────────────────────────────────────────────

if [ "${1:-}" = "--clean" ]; then
    systemctl is-active --quiet "${UNIT_NAME}.service" 2>/dev/null && \
        systemctl stop "${UNIT_NAME}.service" && log "stopped ${UNIT_NAME}.service"
    systemctl reset-failed "${UNIT_NAME}.service" 2>/dev/null || true
    rm -f "$CRED_FILE"
    log "removed $CRED_FILE"
    rm -f "$KEYRING_SECRET_FILE"
    log "removed $KEYRING_SECRET_FILE"
    echo; echo "Clean."; exit 0
fi

# ── Prerequisites ─────────────────────────────────────────────────────────────

info "Checking prerequisites"

command -v g++           &>/dev/null || die "g++ not found — install build-essential"
command -v make          &>/dev/null || die "make not found — install build-essential"
command -v systemd-creds &>/dev/null || die "systemd-creds not found (need systemd v250+)"
command -v systemd-run   &>/dev/null || die "systemd-run not found"
log "srvguard binary:  $SRVGUARD_BIN"

SYSTEMD_VER=$(systemctl --version | awk 'NR==1{print $2}')
[ "$SYSTEMD_VER" -ge 250 ]          || die "systemd v250+ required (have $SYSTEMD_VER)"
log "systemd version: $SYSTEMD_VER"

# Verify credential support and report which backend is active
if systemd-creds has-tpm2 &>/dev/null; then
    log "credential backend: TPM2 (hardware-bound)"
elif [ -f /var/lib/systemd/credential.secret ]; then
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
[ "$VERIFY" = "$TEST_SECRET" ] || die "credential verify failed"
log "decrypt verified OK"
unset TEST_SECRET VERIFY

# ── Launch transient service ──────────────────────────────────────────────────

info "Launching transient service: ${UNIT_NAME}.service"

echo
echo "  Files visible to the admin:"
echo "    encrypted credential:  $CRED_FILE"
echo "    keyring secret:        $KEYRING_SECRET_FILE  (32 random bytes, created by srvguard)"
echo
echo "  Chain:"
echo "    systemd LoadCredentialEncrypted= → \$CREDENTIALS_DIRECTORY/$CRED_NAME"
echo "    srvguard (local mode)            → keyring secret + boot_id → derived label"
echo "                                     → kernel keyring {\"$CRED_NAME\":\"...\"}"
echo "    example binary                   → derive same label → SrvGuardKeyringRead → revoke → zero"
echo

systemctl is-active --quiet "${UNIT_NAME}.service" 2>/dev/null && \
    systemctl stop "${UNIT_NAME}.service"
systemctl reset-failed "${UNIT_NAME}.service" 2>/dev/null || true

SINCE=$(date -Iseconds)
systemd-run \
    --unit="${UNIT_NAME}" \
    --service-type=oneshot \
    --property="LoadCredentialEncrypted=${CRED_NAME}:${CRED_FILE}" \
    --setenv=SRVGUARD_AUTH_METHOD=local \
    --setenv=SRVGUARD_SYSTEMD_CRED="${CRED_NAME}" \
    --setenv=SRVGUARD_OUTPUT_MODE=keyring \
    --setenv=SRVGUARD_KEYRING_SECRET_FILE="${KEYRING_SECRET_FILE}" \
    "$SRVGUARD_BIN" -- "$EXAMPLE_BIN"

# ── Result ────────────────────────────────────────────────────────────────────

info "Result"
sleep 1
journalctl -u "${UNIT_NAME}.service" --no-pager -o cat --since "$SINCE" | grep -v "^$"

echo
echo "  Next step: demo-transient.sh — same flow with Vault in the middle"
