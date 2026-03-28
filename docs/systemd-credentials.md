# systemd Credentials

## What They Are

systemd credentials are service-scoped secrets injected into services at
startup by the service manager. They can optionally be encrypted at rest.
They are the systemd-native answer to the question: *how does a service get
a secret without storing it in a config file?*

Introduced in systemd v250 (released December 2021), credentials are
available on distributions shipping systemd v250 or newer — including
RHEL 9+, Debian 12+, and Ubuntu 22.04+.

## How They Work

**Provisioning (once, by an operator or automation):**

```sh
# Encrypt a Vault token for a specific machine and service
systemd-creds encrypt --name=vault-token - /etc/srvguard/vault-token.cred
```

The credential is encrypted using TPM2 (if available) or a machine-specific
secret stored in `/var/lib/systemd/credential.secret`. The resulting `.cred`
file cannot be decrypted elsewhere unless that machine secret is also copied.

**Delivery (automatic, at service start):**

In the unit file:
```ini
[Service]
LoadCredentialEncrypted=vault-token:/etc/srvguard/vault-token.cred
```

systemd decrypts the credential before starting the service and places the
plaintext in `$CREDENTIALS_DIRECTORY/<name>`. The directory is:
- On a `tmpfs` mount — memory-backed, not intentionally written to disk
  (though kernel memory may still be captured in swap or hibernation images)
- Owned by the service user
- Mode `0500` — inaccessible to other unprivileged users and services
- Removed when the service stops as part of systemd cleanup

The service reads the secret from `$CREDENTIALS_DIRECTORY/vault-token`. By the
time the service sees it, decryption is complete and the secret is in memory.

## Security Properties

**Encrypted at rest:** the `.cred` file stored in `/etc/srvguard/` is
ciphertext. Disk access alone does not reveal the secret unless the
machine-specific key (`credential.secret` or TPM2) is also compromised.

**Machine-bound (with TPM2):** when TPM2 is available, the encryption key
is hardware-bound and the credential cannot be decrypted on another machine.
Without TPM2, the binding is only as strong as the protection of
`/var/lib/systemd/credential.secret`.

**Memory-only at runtime:** `$CREDENTIALS_DIRECTORY` lives in tmpfs. The
plaintext secret is not intentionally written to persistent storage during
service execution, though it may appear in swap or hibernation images.

**Service-scoped:** each service gets its own `$CREDENTIALS_DIRECTORY`.
Other unprivileged services on the same host cannot read another service's
credentials — enforced via mount namespaces and file permissions. Privileged
processes (root) can bypass these controls.

**No daemon process required:** unlike Vault Agent or similar, systemd
credentials need no running sidecar. The service manager handles decryption as
part of normal service startup.

## Comparison with Alternatives

| Mechanism            | Encrypted at rest | Memory-only runtime | Machine-bound    | Service-scoped        |
|----------------------|-------------------|---------------------|------------------|-----------------------|
| systemd credential   | ✓ (with Encrypted=) | ✓ (tmpfs)         | ✓ with TPM2      | ✓                     |
| Environment variable | ✗                 | ✗                   | ✗                | ✗                     |
| File on disk         | ✗                 | ✗                   | ✗                | ✗                     |
| Vault Agent          | ✓                 | Optional            | ✗                | Optional              |
| Linux kernel keyring | N/A               | ✓                   | ✗                | ✓ (per user/session)  |

## How srvguard Uses Them

When `SRVGUARD_AUTH_METHOD=systemd`, srvguard reads
`$CREDENTIALS_DIRECTORY/$SRVGUARD_SYSTEMD_CRED` (default: `vault-token`) and
uses the content as a pre-issued Vault token. No login HTTP call is made — the
token is the credential.

This means the Vault authentication step has no network round-trip: the token
is already present in memory before srvguard starts. No authentication
exchange is required — the token is pre-issued and Vault validates it
directly on the first secret request.

The typical deployment on a VM:

```
operator                 systemd                  srvguard              Vault
   │                        │                        │                    │
   │  systemd-creds encrypt │                        │                    │
   │  vault-token.cred      │                        │                    │
   │───────────────────────►│                        │                    │
   │                        │  service start         │                    │
   │                        │  decrypt → tmpfs       │                    │
   │                        │───────────────────────►│                    │
   │                        │                        │  GET /v1/secret/.. │
   │                        │                        │───────────────────►│
   │                        │                        │◄───────────────────│
   │                        │                        │  write to tmpfs    │
   │                        │                        │  signal NGINX      │
```

## Practical Notes

- `systemd-creds` is in the `systemd` package — no additional install needed
- Use `LoadCredentialEncrypted=` for secrets (TPM2/machine-bound encryption)
- Use `LoadCredential=` for non-secret data that must just be injected
- On containers: systemd is often not PID 1; use the file-on-tmpfs approach
  instead and let the host VM manage credentials for the container
- Re-provisioning: encrypt a new token, replace the `.cred` file, restart the
  service — no host reboot required

## References

- `systemd.exec(5)` — `LoadCredential=` and `LoadCredentialEncrypted=` directives
- `systemd-creds(1)` — command-line tool for credential management
- [systemd credentials documentation](https://systemd.io/CREDENTIALS/)
- [Lennart Poettering: Credentials, 2021](https://systemd.io/CREDENTIALS/)
