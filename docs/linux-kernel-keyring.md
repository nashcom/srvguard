# Linux Kernel Keyring

## What It Is

The Linux kernel keyring is an in-kernel storage facility for small secrets —
passwords, tokens, cryptographic keys — stored in kernel memory and not
exposed via normal userspace interfaces. Secrets placed in the keyring are
not directly written to disk by the keyring subsystem, and survive only as
long as the keyring that holds them exists.

It was introduced in Linux 2.6.10 and is present in every modern Linux
distribution. No additional software is required.

## Key Concepts

**Key:** a named blob of data stored by the kernel. Has a type (`user`,
`logon`, etc.), a description (the lookup name), and a payload (the secret).

**Keyring:** a container for keys. Keys are attached to a keyring; when the
keyring is destroyed, all keys in it are destroyed.

**Session keyring:** created when a process session starts, destroyed when it
ends. Each login session or service invocation gets its own keyring that is
isolated by default from other sessions, unless explicitly shared or accessed
by a sufficiently privileged process.

**Key permissions:** each key has owner/group/other permission bits controlling
who can read, write, search, or link it. A key created by `srvguard` with
`0600` permissions is unreadable by any other user.

## Why It Matters for Secrets

The keyring provides properties that files on disk cannot:

- **Not written to disk by the subsystem:** the keyring itself does not write
  payloads to the filesystem or any disk buffer. Kernel memory can theoretically
  be swapped or captured in a hibernation image or crash dump, but the keyring
  does not actively persist secrets — unlike a file or environment variable.
- **Lifecycle-bound:** a key attached to a session keyring is automatically
  destroyed when the session ends — no cleanup required.
- **Kernel-enforced access control:** the kernel enforces permissions on every
  read attempt. Key payload is not exposed via `/proc` — though key metadata
  (serial number, description) may be visible in `/proc/keys`. Even root
  cannot read a key payload owned by another user without `CAP_SYS_ADMIN`.
- **Read-once pattern:** the consumer reads the key payload once and
  immediately revokes it. After revocation the key is gone — any second read
  fails, even by the original owner.

## How srvguard Uses It

When `SRVGUARD_OUTPUT_MODE=keyring`, srvguard serialises the fetched secret
data to JSON and stores it in the session keyring under the configured label
(`SRVGUARD_KEYRING_LABEL`).

The consuming process — for example a Domino Extension Manager hook — calls
`keyctl search` to find the key by label, reads the payload, and immediately
calls `keyctl revoke`. After revocation the key no longer exists in the
keyring. If the consumer crashes before reading, the key is destroyed when the
session ends.

```
srvguard                              consumer
  │                                       │
  │  add_key("user", "srvguard", data)    │
  │─────────────────────────────────────► │  kernel keyring
  │                                       │  [key: srvguard]
  │                          keyctl read  │◄─────────────────
  │                        keyctl revoke  │─────────────────►
  │                                       │  [key destroyed]
```

## Syscalls

The keyring is accessed via the `keyctl(2)` and `add_key(2)` syscalls. No
external library is required — srvguard calls them directly via the Go
`syscall` package.

| Operation | Syscall |
|---|---|
| Store key | `add_key(2)` |
| Read key payload | `keyctl(KEYCTL_READ)` |
| Revoke key | `keyctl(KEYCTL_REVOKE)` |
| Search by description | `keyctl(KEYCTL_SEARCH)` |

## References

- `keyrings(7)` — Linux man page: overview of the keyring facility
- `keyctl(1)` — command-line tool for keyring management (package: `keyutils`)
- `add_key(2)`, `keyctl(2)` — syscall reference pages
- [Kernel docs: security/keys/core.rst](https://www.kernel.org/doc/html/latest/security/keys/core.html)
