// srvguard.hpp — srvguard C++ consumer library
// Read secrets written by srvguard from either the Linux kernel keyring
// or the files backend. Designed to be included in any native application —
// no Vault dependency, no curl, no external libraries required.
//
// Usage (keyring backend):
//   char szPassword[512] = {};
//   if (SrvGuardKeyringRead("srvguard", "key_password", szPassword, sizeof(szPassword)))
//       // use szPassword — key is removed from keyring after read
//
// Usage (files backend):
//   char szChain[65536] = {};
//   if (SrvGuardFileRead("/run/srvguard/certs", "server.crt", szChain, sizeof(szChain)))
//       // use szChain

#pragma once

#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

// SrvGuardDeriveKeyLabel derives the keyring label from:
//   SHA256( build_salt || external_secret || boot_id )
// build_salt    — hex constant baked into both binaries at compile time
//                 (KEYRING_BUILD_SALT / SRVGUARD_BUILD_SALT).
// external_secret — 32 random bytes in SRVGUARD_KEYRING_SECRET_FILE
//                 (default /var/lib/srvguard/keyring.secret), created by
//                 srvguard on first run, mode 0400, never in source control.
// boot_id       — /proc/sys/kernel/random/boot_id, changes every reboot.
// Result: opaque 32-char hex label — different every boot, not guessable
// without both inputs.  pszLabel must be at least 33 bytes.
// Returns true on success, false if the external secret file cannot be read.
bool SrvGuardDeriveKeyLabel (char *pszLabel, size_t nLabelLen);

// SrvGuardKeyringRead reads a single field from the session keyring secret
// stored under pszLabel, copies it into pszValue, then immediately revokes
// the key via KEYCTL_REVOKE so it cannot be read again.
// Use this for final consumption — the key is gone after this call.
// Returns true on success, false if the key is not found or the field is missing.
bool SrvGuardKeyringRead (const char *pszLabel,
                          const char *pszField,
                          char       *pszValue,
                          size_t      nMaxLen);

// SrvGuardKeyringPeek reads a single field from the session keyring secret
// stored under pszLabel, copies it into pszValue, but does NOT revoke the key.
// Use this when a subsequent read of the same key is expected — for example
// when MainEntryPoint needs the password to initialise a previously-passwordless
// ID, and EM_GETPASSWORD will later consume the same key via SrvGuardKeyringRead.
// Returns true on success, false if the key is not found or the field is missing.
bool SrvGuardKeyringPeek (const char *pszLabel,
                          const char *pszField,
                          char       *pszValue,
                          size_t      nMaxLen);

// SrvGuardFileRead reads the contents of pszFile inside pszDir into pszValue.
// Intended for the files backend — reads server.crt, server.key, ssl.password.
// Returns true on success.
bool SrvGuardFileRead (const char *pszDir,
                       const char *pszFile,
                       char       *pszValue,
                       size_t      nMaxLen);

// SrvGuardZero overwrites a buffer with zeros.
// Use after consuming a secret to prevent it lingering in memory.
void SrvGuardZero (void *pBuf, size_t nLen);

#ifdef __cplusplus
}
#endif
