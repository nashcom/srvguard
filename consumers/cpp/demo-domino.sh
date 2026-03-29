#!/bin/sh
# demo-domino.sh — populate the srvguard keyring for domsrvguard testing
#
# Three scenarios, each writes a JSON payload to the Linux session keyring
# under the label "srvguard". Start Domino from the same session after
# running one of these.
#
# Scenarios:
#   normal   — server.id already has a password, normal unlock
#   setup    — server.id has no password yet, DomSrvGuardSetup=1 required
#   rollover — rotate to a new password on next unlock
#
# Usage:
#   ./demo-domino.sh normal
#   ./demo-domino.sh setup
#   ./demo-domino.sh rollover
#
# Requirements:
#   - Linux kernel keyring  (keyctl)
#   - domsrvguard.so built and deployed to Domino addin directory
#   - notes.ini: EXTMGR_ADDINS=domsrvguard  (or EXTMGR_ADDINS_EARLY for TXN log)
#   - notes.ini: KeyFilename=<path to server.id>  (setup scenario only)

set -eu

KEYRING_LABEL="srvguard"

log()  { printf '  %s\n' "$*"; }
info() { printf '\n── %s ──\n' "$*"; }
die()  { printf 'ERROR: %s\n' "$*" >&2; exit 1; }

command -v keyctl >/dev/null 2>&1 || die "keyctl not found — install keyutils"

# ── Scenario: normal unlock ────────────────────────────────────────────────────
#
# server.id already has a password. srvguard reads it from the keyring and
# returns it to Domino via EM_GETPASSWORD. Key is revoked after the read.
#
# Expected console output:
#   DomSrvGuard[server]: Password returned: 9
#
do_normal()
{
    PW='DontPanic'
    PAYLOAD="{\"password\":\"${PW}\"}"

    info "Scenario: normal unlock"
    log "password:  $PW"
    log "payload:   $PAYLOAD"
    log "label:     $KEYRING_LABEL"

    printf '%s' "$PAYLOAD" | keyctl padd user "$KEYRING_LABEL" @s
    log "key written to session keyring"

    printf '\n  notes.ini — nothing special required:\n'
    printf '    EXTMGR_ADDINS=domsrvguard\n'
    printf '\n  Start Domino. Expected console:\n'
    printf '    DomSrvGuard[server]: Password returned: %d\n' "${#PW}"
}

# ── Scenario: initial setup ────────────────────────────────────────────────────
#
# server.id has no password yet. MainEntryPoint detects DomSrvGuardSetup=1,
# calls SrvGuardKeyringPeek (key stays), calls SECKFMChangePassword to set the
# password, then EM_GETPASSWORD fires, reads and revokes the key, Domino unlocks.
# DomSrvGuardSetup is cleared from notes.ini automatically.
#
# Expected console output:
#   DomSrvGuard[server]: Initial password set
#   DomSrvGuard[server]: Password returned: 2
#
do_setup()
{
    PW='FortyTwo'
    PAYLOAD="{\"password\":\"${PW}\"}"

    info "Scenario: initial setup (passwordless server.id)"
    log "password:  $PW  (the answer to life, the universe, and everything)"
    log "payload:   $PAYLOAD"
    log "label:     $KEYRING_LABEL"

    printf '%s' "$PAYLOAD" | keyctl padd user "$KEYRING_LABEL" @s
    log "key written to session keyring"

    printf '\n  notes.ini — set before starting Domino:\n'
    printf '    EXTMGR_ADDINS=domsrvguard\n'
    printf '    DomSrvGuardSetup=1\n'
    printf '    KeyFilename=/local/notesdata/server.id\n'
    printf '\n  Start Domino. Expected console:\n'
    printf '    DomSrvGuard[server]: Initial password set\n'
    printf '    DomSrvGuard[server]: Password returned: %d\n' "${#PW}"
    printf '\n  DomSrvGuardSetup is removed from notes.ini automatically.\n'
    printf '  Subsequent restarts use the normal unlock scenario.\n'
}

# ── Scenario: password rollover ────────────────────────────────────────────────
#
# Both password (current) and new_password (next) are present. EM_GETPASSWORD
# detects new_password, calls SECKFMChangePassword to rotate the ID, then
# returns the new password so Domino unlocks with it. Both keys are revoked.
# On next restart only the new password is needed.
#
# Expected console output:
#   DomSrvGuard[server]: Password rollover complete
#   DomSrvGuard[server]: Password returned: 20
#
do_rollover()
{
    PW='DontPanic'
    NEW_PW='FortyTwo'
    PAYLOAD="{\"password\":\"${PW}\",\"new_password\":\"${NEW_PW}\"}"

    info "Scenario: password rollover"
    log "current password:  $PW"
    log "new password:      $NEW_PW"
    log "payload:           $PAYLOAD"
    log "label:             $KEYRING_LABEL"

    printf '%s' "$PAYLOAD" | keyctl padd user "$KEYRING_LABEL" @s
    log "key written to session keyring"

    printf '\n  notes.ini — nothing special required:\n'
    printf '    EXTMGR_ADDINS=domsrvguard\n'
    printf '\n  Start Domino. Expected console:\n'
    printf '    DomSrvGuard[server]: Password rollover complete\n'
    printf '    DomSrvGuard[server]: Password returned: %d\n' "${#NEW_PW}"
    printf '\n  On next restart provision only: {"password":"%s"}\n' "$NEW_PW"
    printf '  Use the normal scenario from that point on.\n'
}

# ── Dispatch ───────────────────────────────────────────────────────────────────

case "${1:-}" in
    normal)   do_normal   ;;
    setup)    do_setup    ;;
    rollover) do_rollover ;;
    *)
        printf 'Usage: %s normal|setup|rollover\n' "$0"
        printf '\n'
        printf '  normal    server.id has a password — normal unlock via EM_GETPASSWORD\n'
        printf '  setup     server.id has no password yet — DomSrvGuardSetup=1 required\n'
        printf '  rollover  rotate to a new password on next Domino unlock\n'
        exit 1
        ;;
esac

printf '\n'
