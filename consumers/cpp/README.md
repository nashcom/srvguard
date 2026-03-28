# srvguard C++ consumer

*by Nash!Com*

> **TL;DR —** A header-only C++ library that reads secrets from the Linux kernel
> keyring or the files backend. Drop `srvguard.hpp` and `srvguard.cpp` into any
> native application. No Vault dependency, no curl, no external libraries — just
> standard C++ and Linux syscalls.

---

## The security chain

When srvguard delivers a secret it never writes it to a world-readable file or
an environment variable. The path from disk to your application is:

```
systemd (LoadCredentialEncrypted=)
  │  machine-encrypted .cred file — useless without this machine's key
  │
  ▼
$CREDENTIALS_DIRECTORY/<name>
  │  tmpfs, private mount namespace, service-scoped, deleted on stop
  │
  ▼
srvguard
  │  reads the credential, authenticates to Vault (or passes through in local mode)
  │  writes the secret into the kernel keyring
  │
  ▼
kernel keyring {"field":"value"}
  │  kernel memory, not in any filesystem, session-scoped
  │
  ▼
your application
  SrvGuardKeyringRead(...)   — read once, key revoked, buffer zeroed
```

The secret exists in plaintext for milliseconds — in kernel memory, in one
service's session, read once and gone.

## Consumption patterns

Three patterns cover most real-world deployments. The consumer library API is
identical in all three.

### Pattern 1 — local secret, no Vault

A secret (server.id password, API key, certificate password) is protected by
systemd and delivered directly to the application. No Vault, no network.

```
systemd  →  srvguard (local mode)  →  keyring  →  application
```

Use this when:
- You want strong secret protection without Vault infrastructure
- The secret is machine-specific (server.id password, local API key)
- You need a fast on-ramp — Vault can be added later without touching the app

### Pattern 2 — Vault-backed secret

srvguard authenticates to Vault, fetches secrets, and delivers them to the
keyring. The application never holds Vault credentials.

```
systemd  →  srvguard  →  Vault  →  keyring  →  application
```

Use this when:
- Secrets are managed centrally and rotated automatically
- You need audit trails, lease expiry, and dynamic secrets
- Multiple servers share the same secret path

### Pattern 3 — file backend (nginx, legacy apps)

Some applications cannot use the keyring API. srvguard writes to a tmpfs
directory instead. The file is still service-scoped and disappears on stop.

```
systemd  →  srvguard  →  /run/srvguard/certs/  →  application reads file
```

Use this when:
- Integrating with nginx `ssl_password_file`, certificate reload hooks, or
  any application that reads configuration files at startup

## Building

```bash
cd consumers/cpp
make
```

Produces `libsrvguard.a` and the `example` demo binary. Requires `g++` with
C++17 support — no external dependencies.

## Running the demo

`demo.sh` walks through Pattern 1 end to end. It encrypts a test secret with
`systemd-creds`, runs srvguard in local mode, and launches the `example` binary
as the child process. The example binary reads the secret from the keyring,
prints it, revokes the key, and zeros the buffer.

The demo uses a [transient systemd service](https://www.freedesktop.org/software/systemd/man/systemd-run.html)
(`systemd-run`) for convenience — no unit file needed, everything is cleaned up
on exit.

```bash
# run the full demo
sudo ./demo.sh

# clean up afterwards
sudo ./demo.sh --clean
```

What you will see:

```
── Building example consumer ──
── Encrypting test secret ──
  secret value:  demo-password-1743163489
  encrypted to:  /tmp/srvguard-keyring-demo.cred
  decrypt verified OK
── Launching transient service ──
  Chain:
    systemd LoadCredentialEncrypted= → $CREDENTIALS_DIRECTORY/key_password
    srvguard (local mode)            → kernel keyring {"key_password":"..."}
    example binary                   → SrvGuardKeyringRead → revoke → zero
── Result ──
  keyring: got password (26 chars)
  ✓ systemd credential decrypted into $CREDENTIALS_DIRECTORY
  ✓ srvguard loaded it into the kernel keyring
  ✓ example consumer read it — key revoked, memory zeroed
```

## Library API

```cpp
#include "srvguard.hpp"

// Read one field from the kernel keyring.
// The key is revoked immediately after reading — one-time access.
bool SrvGuardKeyringRead (const char *pszLabel,   // keyring key label (SRVGUARD_KEYRING_LABEL)
                          const char *pszField,   // JSON field name
                          char       *pszValue,   // output buffer
                          size_t      nMaxLen);

// Read a file written by srvguard's files backend.
bool SrvGuardFileRead    (const char *pszDir,     // SRVGUARD_OUTPUT_DIR or $CREDENTIALS_DIRECTORY
                          const char *pszFile,    // field name / filename
                          char       *pszValue,
                          size_t      nMaxLen);

// Zero a buffer — volatile, not optimised away by the compiler.
void SrvGuardZero        (void *pBuf, size_t nLen);
```

## Integration example — Domino Extension Manager

The EM calls `SrvGuardKeyringRead` at startup before the server.id password is
needed. srvguard must have loaded the keyring before Domino starts — handled
automatically when srvguard is the process supervisor (`ExecStart=/bin/srvguard
/opt/domino/bin/server`).

```cpp
char szPassword[512] = {};

if (SrvGuardKeyringRead("srvguard", "server_id_password",
                         szPassword, sizeof(szPassword)))
{
    // hand szPassword to the Notes C API
    // srvguard has already revoked the key — it cannot be read again
    SrvGuardZero(szPassword, sizeof(szPassword));
}
```

No Vault code, no token handling, no certificate management in the EM. srvguard
handles all of that. The EM just reads one field and zeros the buffer.

## Next step

Once Pattern 1 works in your environment, switching to Vault (Pattern 2)
requires only a change to the srvguard configuration — no application code
changes. The keyring API and the consumer binary stay identical.

See [`docs/architecture.md`](../../docs/architecture.md) for the full picture.
