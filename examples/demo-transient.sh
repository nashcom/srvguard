#!/bin/bash
# srvguard — transient service demo
#
# Walks through the full flow from credential encryption to a running
# srvguard instance launched as a transient systemd service.
# Intended for demos and testing — not for production deployments.
#
# Usage:
#   ./demo-transient.sh              # interactive — prompts for all values
#   ./demo-transient.sh --clean      # stop and remove the transient service

set -euo pipefail

# ── Configuration ─────────────────────────────────────────────────────────────

UNIT_NAME="srvguard-demo"
SRVGUARD_BIN="${SRVGUARD_BIN:-/bin/srvguard}"
CRED_FILE="${CRED_FILE:-/tmp/${CRED_NAME}}"
CRED_NAME="vault-token"
OUTPUT_DIR="/run/srvguard-demo/secrets"

# ── Helpers ───────────────────────────────────────────────────────────────────

log()  { echo "  $*"; }
info() { echo; echo "── $* ──"; }
die()  { echo "ERROR: $*" >&2; exit 1; }

ask() {
    local prompt="$1" default="${2:-}" var
    if [[ -n "$default" ]]; then
        read -rp "  $prompt [$default]: " var
        echo "${var:-$default}"
    else
        read -rp "  $prompt: " var
        echo "$var"
    fi
}

ask_secret() {
    local prompt="$1" var
    read -rsp "  $prompt: " var
    echo
    echo "$var"
}

require() {
    command -v "$1" &>/dev/null || die "$1 not found — $2"
}

# ── Clean up ──────────────────────────────────────────────────────────────────

if [[ "${1:-}" == "--clean" ]]; then
    info "Stopping transient service"
    if systemctl is-active --quiet "${UNIT_NAME}.service" 2>/dev/null; then
        systemctl stop "${UNIT_NAME}.service"
        log "stopped ${UNIT_NAME}.service"
    else
        log "${UNIT_NAME}.service is not running"
    fi
    rm -f "$CRED_FILE"
    log "removed $CRED_FILE"
    echo
    echo "Clean."
    exit 0
fi

# ── Prerequisites ─────────────────────────────────────────────────────────────

info "Checking prerequisites"

require systemd-creds "install systemd (v250+)"
require systemd-run   "install systemd (v250+)"
require systemctl     "install systemd"

[[ -x "$SRVGUARD_BIN" ]] || die "$SRVGUARD_BIN not found — export SRVGUARD_BIN=/path/to/srvguard"
log "srvguard binary: $SRVGUARD_BIN"

SYSTEMD_VER=$(systemctl --version | awk 'NR==1{print $2}')
log "systemd version: $SYSTEMD_VER"
[[ "$SYSTEMD_VER" -ge 250 ]] || die "systemd v250+ required (have $SYSTEMD_VER)"

# ── Gather configuration ──────────────────────────────────────────────────────

info "Configuration"

VAULT_ADDR=$(ask    "Vault address"      "${VAULT_ADDR:-https://127.0.0.1:8200}")
SECRET_FQDN=$(ask   "Server FQDN"       "$(hostname -f 2>/dev/null || hostname)")
MAIL_TO=$(ask       "Alert mail to"     "${SRVGUARD_MAIL_TO:-}")
MAIL_RELAY=$(ask    "Mail relay host"   "${SRVGUARD_MAIL_RELAY:-}")
CHILD_CMD=$(ask     "Child command"     "sleep 300")

echo
VAULT_TOKEN=$(ask_secret "Vault token (input hidden)")
[[ -n "$VAULT_TOKEN" ]] || die "Vault token is required"

# ── Encrypt credential ────────────────────────────────────────────────────────

info "Encrypting Vault token"

echo -n "$VAULT_TOKEN" | \
    systemd-creds encrypt - "$CRED_FILE"

log "encrypted credential: $CRED_FILE"

# Verify round-trip
VERIFY=$(systemd-creds decrypt "$CRED_FILE" - 2>/dev/null) || die "credential verify failed"
[[ "$VERIFY" == "$VAULT_TOKEN" ]] || die "credential decrypt mismatch"
log "credential verified OK"

# Clear token from memory as soon as possible
unset VAULT_TOKEN VERIFY

# ── Build systemd-run command ─────────────────────────────────────────────────

info "Launching transient service: ${UNIT_NAME}.service"

SETENV=(
    "--setenv=SRVGUARD_ADDR=${VAULT_ADDR}"
    "--setenv=SRVGUARD_AUTH_METHOD=systemd"
    "--setenv=SRVGUARD_SYSTEMD_CRED=${CRED_NAME}"
    "--setenv=SRVGUARD_SECRET_FQDN=${SECRET_FQDN}"
    "--setenv=SRVGUARD_OUTPUT_DIR=${OUTPUT_DIR}"
)

[[ -n "$MAIL_TO"    ]] && SETENV+=("--setenv=SRVGUARD_MAIL_TO=${MAIL_TO}")
[[ -n "$MAIL_RELAY" ]] && SETENV+=("--setenv=SRVGUARD_MAIL_RELAY=${MAIL_RELAY}")

# Print the effective command for transparency
echo
echo "  systemd-run \\"
echo "      --unit=${UNIT_NAME} \\"
echo "      --service-type=simple \\"
echo "      --property=LoadCredentialEncrypted=${CRED_NAME}:${CRED_FILE} \\"
for e in "${SETENV[@]}"; do
    echo "      ${e} \\"
done
echo "      ${SRVGUARD_BIN} ${CHILD_CMD}"
echo

# Stop any previous instance
if systemctl is-active --quiet "${UNIT_NAME}.service" 2>/dev/null; then
    log "stopping previous instance"
    systemctl stop "${UNIT_NAME}.service"
fi
systemctl reset-failed "${UNIT_NAME}.service" 2>/dev/null || true

# Launch
# shellcheck disable=SC2086
systemd-run \
    --unit="${UNIT_NAME}" \
    --service-type=simple \
    --property="LoadCredentialEncrypted=${CRED_NAME}:${CRED_FILE}" \
    "${SETENV[@]}" \
    "$SRVGUARD_BIN" $CHILD_CMD

# ── Status ────────────────────────────────────────────────────────────────────

info "Service status"
sleep 1
systemctl status "${UNIT_NAME}.service" --no-pager -l || true

# ── Log tail ──────────────────────────────────────────────────────────────────

info "Log output (Ctrl-C to stop following)"
echo "  (run  ./demo-transient.sh --clean  to stop the service)"
echo
journalctl -u "${UNIT_NAME}.service" -f --no-pager
