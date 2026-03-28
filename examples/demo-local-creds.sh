#!/bin/bash
# srvguard — local systemd credential demo
#
# Tests the full systemd credential path without Vault:
#
#   1. Encrypt a test secret with systemd-creds
#   2. Launch a transient service with LoadCredentialEncrypted=
#   3. Child process reads the secret from $CREDENTIALS_DIRECTORY
#   4. Verify the secret arrived intact
#
# No Vault, no network, no auth — pure systemd credential delivery.
#
# Usage:
#   ./demo-local-creds.sh
#   ./demo-local-creds.sh --clean

set -euo pipefail

UNIT_NAME="srvguard-local-demo"
CRED_NAME="test-secret"
CRED_FILE="/tmp/${CRED_NAME}"

log()  { echo "  $*"; }
info() { echo; echo "── $* ──"; }
die()  { echo "ERROR: $*" >&2; exit 1; }

# ── Clean ─────────────────────────────────────────────────────────────────────

if [[ "${1:-}" == "--clean" ]]; then
    systemctl is-active --quiet "${UNIT_NAME}.service" 2>/dev/null && \
        systemctl stop "${UNIT_NAME}.service" && log "stopped ${UNIT_NAME}.service"
    rm -f "$CRED_FILE"
    log "removed $CRED_FILE"
    echo; echo "Clean."; exit 0
fi

# ── Prerequisites ─────────────────────────────────────────────────────────────

info "Checking prerequisites"

command -v systemd-creds &>/dev/null || die "systemd-creds not found (need systemd v250+)"
command -v systemd-run  &>/dev/null || die "systemd-run not found"

SYSTEMD_VER=$(systemctl --version | awk 'NR==1{print $2}')
log "systemd version: $SYSTEMD_VER"
[[ "$SYSTEMD_VER" -ge 250 ]] || die "systemd v250+ required (have $SYSTEMD_VER)"

# ── Create and encrypt a test secret ─────────────────────────────────────────

info "Creating test secret"

TEST_SECRET="srvguard-local-test-$(date +%s)"
log "secret value: $TEST_SECRET"

echo -n "$TEST_SECRET" | systemd-creds encrypt - "$CRED_FILE"
log "encrypted: $CRED_FILE"

# Verify round-trip before trusting it
VERIFY=$(systemd-creds decrypt "$CRED_FILE" -)
[[ "$VERIFY" == "$TEST_SECRET" ]] || die "credential verify failed"
log "decrypt verified OK"

# ── Launch transient service ──────────────────────────────────────────────────

info "Launching transient service: ${UNIT_NAME}.service"

# The child command reads the credential from $CREDENTIALS_DIRECTORY,
# writes it to the journal, and compares it to the original value.
CHILD='
    val=$(cat "$CREDENTIALS_DIRECTORY/'"$CRED_NAME"'")
    echo "CREDENTIALS_DIRECTORY: $CREDENTIALS_DIRECTORY"
    echo "secret received:       $val"
    if [ "$val" = "'"$TEST_SECRET"'" ]; then
        echo "RESULT: OK -- secret matches"
    else
        echo "RESULT: FAIL -- secret mismatch"
        exit 1
    fi
'

echo
echo "  systemd-run \\"
echo "      --unit=${UNIT_NAME} \\"
echo "      --service-type=oneshot \\"
echo "      --property=LoadCredentialEncrypted=${CRED_NAME}:${CRED_FILE} \\"
echo "      bash -c '...'"
echo

systemctl is-active --quiet "${UNIT_NAME}.service" 2>/dev/null && \
    systemctl stop "${UNIT_NAME}.service"
systemctl reset-failed "${UNIT_NAME}.service" 2>/dev/null || true

systemd-run \
    --unit="${UNIT_NAME}" \
    --service-type=oneshot \
    --property="LoadCredentialEncrypted=${CRED_NAME}:${CRED_FILE}" \
    bash -c "$CHILD"

# ── Result ────────────────────────────────────────────────────────────────────

info "Result"
sleep 1
journalctl -u "${UNIT_NAME}.service" --no-pager -o cat | grep -v "^$"

echo
if journalctl -u "${UNIT_NAME}.service" --no-pager -o cat | grep -q "RESULT: OK"; then
    echo "  ✓ systemd credential delivery works"
    echo "  ✓ \$CREDENTIALS_DIRECTORY was set and readable"
    echo "  ✓ secret arrived intact"
else
    echo "  ✗ something went wrong — check the output above"
    exit 1
fi

echo
echo "  Next step: demo-transient.sh  (add Vault to the path)"
