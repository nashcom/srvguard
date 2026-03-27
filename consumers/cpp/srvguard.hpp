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

// SrvGuardKeyringRead reads a single field from the session keyring secret
// stored under pszLabel, copies it into pszValue, then immediately revokes
// the key so it cannot be read again.
// Returns true on success, false if the key is not found or the field is missing.
bool SrvGuardKeyringRead (const char *pszLabel,
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
