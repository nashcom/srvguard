# systemd Credentials

## What They Are

systemd credentials are encrypted, service-scoped secrets injected into
services at startup by the service manager. They are the systemd-native answer
to the question: *how does a service get a secret without storing it in a
config file?*

Introduced in systemd v250 (released December 2021, standard in RHEL 9,
Debian 12, Ubuntu 22.04+), credentials are available on every current
enterprise Linux distribution.

## How They Work

**Provisioning (once, by an operator or automation):**

```sh
# Encrypt a Vault token for a specific machine and service
systemd-creds encrypt --name=vault-token - /etc/srvguard/vault-token.cred
```

The credential is encrypted using the machine's TPM2 binding or, on machines
without TPM2, a machine-specific key derived from `/var/lib/systemd/credential.secret`.
The resulting `.cred` file is unreadable on any other machine.

**Delivery (automatic, at service start):**

In the unit file:
```ini
[Service]
LoadCredentialEncrypted=vault-token:/etc/srvguard/vault-token.cred
```

systemd decrypts the credential before starting the service and places the
plaintext in `$CREDENTIALS_DIRECTORY/<name>`. The directory is:
- On a `tmpfs` mount (memory only, never hits disk)
- Owned by the service user
- Mode `0500` — no other user or service can read it
- Destroyed when the service stops

The service reads the secret from `$CREDENTIALS_DIRECTORY/vault-token`. By the
time the service sees it, decryption is complete and the secret is in memory.

## Security Properties

**Encrypted at rest:** the `.cred` file stored in `/etc/srvguard/` is
ciphertext. Even full disk access does not yield the secret.

**Machine-bound:** the encryption key is derived from TPM2 or a machine secret
that does not leave the host. The credential cannot be decrypted on another
machine.

**Memory-only at runtime:** `$CREDENTIALS_DIRECTORY` lives in tmpfs. The
plaintext secret is never written to any persistent storage during service
execution.

**Service-scoped:** each service gets its own `$CREDENTIALS_DIRECTORY`. Other
services on the same host cannot read another service's credentials — enforced
by the kernel via mount namespaces and file permissions.

**No daemon process required:** unlike Vault Agent or similar, systemd
credentials need no running sidecar. The service manager handles decryption as
part of normal service startup.

## Comparison with Alternatives

| Mechanism | Encrypted at rest | Memory-only runtime | Machine-bound | Service-scoped |
|---|---|---|---|---|
| systemd credential | ✓ | ✓ | ✓ | ✓ |
| Environment variable | ✗ | ✗ | ✗ | ✗ |
| File on disk | ✗ | ✗ | ✗ | ✗ |
| Vault Agent | ✓ | Optional | ✗ | Optional |
| Linux kernel keyring | N/A | ✓ | ✗ | ✓ (session) |

## How srvguard Uses Them

When `SRVGUARD_AUTH_METHOD=systemd`, srvguard reads
`$CREDENTIALS_DIRECTORY/$SRVGUARD_SYSTEMD_CRED` (default: `vault-token`) and
uses the content as a pre-issued Vault token. No login HTTP call is made — the
token is the credential.

This means the Vault authentication step has no network round-trip: the token
is already present in memory before srvguard starts. Vault sees an
authenticated request for the secret; it does not need to validate a role or
certificate.

The typical deployment on a VM:

```
operator                 systemd                  srvguard              Vault
   │                        │                        │                    │
   │  systemd-creds encrypt  │                        │                    │
   │  vault-token.cred       │                        │                    │
   │────────────────────────►│                        │                    │
   │                         │  service start         │                    │
   │                         │  decrypt → tmpfs       │                    │
   │                         │───────────────────────►│                    │
   │                         │                        │  GET /v1/secret/.. │
   │                         │                        │───────────────────►│
   │                         │                        │◄───────────────────│
   │                         │                        │  write to tmpfs    │
   │                         │                        │  signal NGINX      │
```

## Practical Notes

- `systemd-creds` is in the `systemd` package — no additional install needed
- Use `LoadCredentialEncrypted=` for secrets (TPM2/machine-bound encryption)
- Use `LoadCredential=` for non-secret data that must just be injected
- On containers: systemd is usually not PID 1; use the file-on-tmpfs approach
  instead and let the host VM manage credentials for the container
- Re-provisioning: encrypt a new token, replace the `.cred` file, restart the
  service — no host reboot required

## References

- `systemd.exec(5)` — `LoadCredential=` and `LoadCredentialEncrypted=` directives
- `systemd-creds(1)` — command-line tool for credential management
- [systemd credentials documentation](https://systemd.io/CREDENTIALS/)
- [Lennart Poettering: Credentials, 2021](https://systemd.io/CREDENTIALS/)
