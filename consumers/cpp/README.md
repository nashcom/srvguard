# srvguard C++ consumer

A C++ library that reads secrets from the Linux kernel keyring. Drop
`srvguard.hpp` and `srvguard.cpp` into any native application — no Vault
dependency, no curl, no external libraries, just standard C++ and Linux syscalls.

---

## The security chain

```
systemd (LoadCredentialEncrypted=)
  │  machine-encrypted .cred file
  ▼
$CREDENTIALS_DIRECTORY/<name>
  │  tmpfs, private mount namespace, service-scoped
  ▼
srvguard
  │  reads the credential, writes the secret into the kernel keyring
  ▼
kernel keyring  {"field":"value"}
  │  kernel memory, session-scoped, not in any filesystem
  ▼
your application
     SrvGuardKeyringRead(...)  — read once, key revoked, buffer zeroed
```

The secret exists in plaintext for milliseconds — in kernel memory, in one
session, read once and gone.

---

## Building

```bash
cd consumers/cpp
make
```

Produces `libsrvguard.a` and the `example` demo binary. Requires `g++` with
C++17 support — no external dependencies.

To build `domsrvguard.so` (requires the Notes C-API):

```bash
make domsrvguard
```

---

## Running the demo

`demo.sh` walks through the full chain end to end — encrypts a test secret with
`systemd-creds`, runs srvguard in local mode, and launches the `example` binary
as the child process. The example binary reads the secret from the keyring,
prints it, revokes the key, and zeros the buffer.

```bash
sudo ./demo.sh
sudo ./demo.sh --clean
```

---

## Library API

```cpp
#include "srvguard.hpp"

// Read one field from the kernel keyring and immediately revoke the key.
// One-time access — the key cannot be read again after this call.
// Use this for final consumption.
bool SrvGuardKeyringRead (const char *pszLabel,   // keyring key label
                          const char *pszField,   // JSON field name
                          char       *pszValue,   // output buffer
                          size_t      nMaxLen);

// Read one field from the kernel keyring without revoking the key.
// Use this when a subsequent read of the same key is expected — for example
// when setup code needs the password before the unlock callback fires.
// SrvGuardKeyringRead in the callback then consumes and revokes the key.
bool SrvGuardKeyringPeek (const char *pszLabel,
                          const char *pszField,
                          char       *pszValue,
                          size_t      nMaxLen);

// Zero a buffer — volatile, not optimised away by the compiler.
// Call after consuming any secret to prevent it lingering in memory.
void SrvGuardZero        (void *pBuf, size_t nLen);
```

---

## domsrvguard — Domino Extension Manager

> **See also:** [Domino CertMgr on GitHub](https://opensource.hcltechsw.com/domino-cert-manager/) —
> [HCL documentation](https://help.hcl-software.com/domino/14.5.1/admin/certificate_management_with_certmgr.html)

`domsrvguard.so` is a Domino Extension Manager that delivers the server.id
password directly from the srvguard kernel keyring. No external process, no
files, no pipes. Domino never prompts for a password.

CertMgr handles all TLS certificate lifecycle on Domino. domsrvguard covers the
one thing CertMgr does not: delivering the server.id password at startup.

### notes.ini variables

| Variable | Required | Description |
|---|---|---|
| `EXTMGR_ADDINS=domsrvguard` | always | Load the extension manager |
| `EXTMGR_ADDINS_EARLY=domsrvguard` | transaction log only | Load before transaction log recovery |
| `KeyFilename=<path>` | initial setup only | Path to server.id used to set the initial password |
| `DomSrvGuardSetup=1` | initial setup only | Triggers initial password set for a passwordless server.id — cleared automatically |
| `DomSrvGuardDebug=1` | optional | Enable verbose logging to the Domino console |

### Keyring payload

srvguard writes a JSON object to the kernel keyring under the label `srvguard`.
domsrvguard reads the following fields:

| Field | Description |
|---|---|
| `password` | Current server.id password |
| `new_password` | New password for rollover — triggers `SECKFMChangePassword` on next unlock |

### Three scenarios

**Normal unlock** — server.id already has a password:
```json
{"password":"DontPanic"}
```

**Initial setup** — server.id has no password yet. Set `DomSrvGuardSetup=1`
and `KeyFilename` in notes.ini before starting Domino. `MainEntryPoint` sets
the password via `SECKFMChangePassword`, then `EM_GETPASSWORD` fires to unlock
the server. `DomSrvGuardSetup` is cleared automatically.
```json
{"password":"FortyTwo"}
```

**Password rollover** — rotate to a new password. Both fields present triggers
`SECKFMChangePassword` inside `EM_GETPASSWORD`. The server unlocks with the new
password. On next restart provision only `password` with the new value.
```json
{"password":"DontPanic","new_password":"FortyTwo"}
```

See `demo-domino.sh` for ready-to-run examples of all three scenarios.
