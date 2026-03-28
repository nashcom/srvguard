# srvguard — systemd Service Integration

*by Nash!Com*

> **TL;DR —** A complete guide to running srvguard as a systemd service.
> Covers encrypting the Vault token with `systemd-creds`, the static unit file,
> and the transient `systemd-run` equivalent for ephemeral workloads.

---

srvguard is designed to run as a systemd service. It acts as the process
supervisor for your workload — fetching secrets from Vault, writing them to a
tmpfs directory or the kernel keyring, launching the child process, and
rotating secrets on schedule without restarting the child.

The Vault token is passed via a `LoadCredentialEncrypted=` entry. systemd
decrypts it at service start using the machine's TPM2 key (or
`/var/lib/systemd/credential.secret` as fallback) and delivers it through
`$CREDENTIALS_DIRECTORY` — a per-service tmpfs path that no other service can
read.

## Prerequisites

- systemd v250 or newer (RHEL 9+, Debian 12+, Ubuntu 22.04+)
- A Vault token or AppRole credentials for srvguard to use
- `/bin/srvguard` installed and executable

## Step 1 — Encrypt the Vault token

Encrypt the Vault token for this machine. The result is a machine-bound
credential file that systemd will decrypt at runtime:

```bash
# interactive — paste token, press Ctrl-D
systemd-creds encrypt --name=vault-token - /etc/srvguard/vault-token.cred

# or pipe directly
echo -n "hvs.XXXXXXXX" | \
    systemd-creds encrypt --name=vault-token - /etc/srvguard/vault-token.cred
```

The `--name=vault-token` must match the credential name used in the unit file.
The encrypted file can only be decrypted on this machine.

Verify the file was created:

```bash
ls -lh /etc/srvguard/vault-token.cred
systemd-creds decrypt /etc/srvguard/vault-token.cred -    # should print the token
```

## Step 2 — Static unit file

Save as `/etc/systemd/system/srvguard-nginx.service` (adjust the child command
for your workload):

```ini
[Unit]
Description=srvguard — nginx with Vault-managed secrets
After=network-online.target vault.service
Wants=network-online.target

[Service]
Type=simple
User=nginx
Group=nginx

# ── Vault token — machine-encrypted, decrypted by systemd into $CREDENTIALS_DIRECTORY
LoadCredentialEncrypted=vault-token:/etc/srvguard/vault-token.cred

# ── Vault connection
Environment=SRVGUARD_ADDR=https://vault.example.com:8200
Environment=SRVGUARD_AUTH_METHOD=systemd
Environment=SRVGUARD_SYSTEMD_CRED=vault-token
Environment=SRVGUARD_SECRET_FQDN=myserver.example.com

# ── Secret output
Environment=SRVGUARD_OUTPUT_DIR=/run/srvguard/secrets

# ── Mail alerts (optional)
Environment=SRVGUARD_MAIL_TO=ops@example.com
Environment=SRVGUARD_MAIL_RELAY=smtp.example.com

# ── Process supervision
ExecStart=/bin/srvguard -- /usr/sbin/nginx -g 'daemon off;'
Restart=on-failure
RestartSec=5s

# ── Runtime directory for secret output (tmpfs-backed, removed on stop)
RuntimeDirectory=srvguard
RuntimeDirectoryMode=0700

[Install]
WantedBy=multi-user.target
```

Enable and start:

```bash
systemctl daemon-reload
systemctl enable --now srvguard-nginx.service
systemctl status srvguard-nginx.service
journalctl -u srvguard-nginx.service -f
```

## Step 3 — Transient service with systemd-run

Transient services are created on the fly with `systemd-run` — no unit file on
disk. They support the same properties as static units including
`LoadCredentialEncrypted=`, making them useful for:

- Testing srvguard configuration before writing a unit file
- Ephemeral workloads that run once and exit
- CI/CD jobs that need Vault secrets at runtime

```bash
systemd-run \
    --unit=srvguard-test \
    --service-type=simple \
    --property=LoadCredentialEncrypted=vault-token:/etc/srvguard/vault-token.cred \
    --setenv=SRVGUARD_ADDR=https://vault.example.com:8200 \
    --setenv=SRVGUARD_AUTH_METHOD=systemd \
    --setenv=SRVGUARD_SYSTEMD_CRED=vault-token \
    --setenv=SRVGUARD_SECRET_FQDN=myserver.example.com \
    --setenv=SRVGUARD_OUTPUT_DIR=/run/srvguard-test/secrets \
    /bin/srvguard -- /usr/sbin/nginx -g 'daemon off;'
```

Check status and follow logs:

```bash
systemctl status srvguard-test.service
journalctl -u srvguard-test.service -f
```

Stop and clean up:

```bash
systemctl stop srvguard-test.service
```

## Static vs transient — comparison

| Property                        | Static unit file          | Transient (systemd-run)       |
| ------------------------------- | ------------------------- | ----------------------------- |
| Survives reboot                 | Yes (if enabled)          | No                            |
| Auto-start on boot              | Yes (`WantedBy=`)         | No                            |
| Dependency ordering             | Full (`After=`, `Wants=`) | Limited (`--property=After=`) |
| Unit file on disk               | Yes                       | No                            |
| `LoadCredentialEncrypted=`      | Yes                       | Yes (`--property=`)           |
| Restart policy                  | Yes (`Restart=on-failure`)| Yes (`--property=Restart=`)   |
| Suitable for production         | Yes                       | Testing / ephemeral only      |

## Credential file locations

| File                                       | Purpose                                      |
| ------------------------------------------ | -------------------------------------------- |
| `/etc/srvguard/vault-token.cred`           | Machine-encrypted Vault token (input)        |
| `$CREDENTIALS_DIRECTORY/vault-token`       | Decrypted token, tmpfs, service-scoped       |
| `/run/srvguard/secrets/`                   | Vault secrets written by srvguard (output)   |

The `$CREDENTIALS_DIRECTORY` path is set by systemd at runtime — srvguard reads
it automatically when `SRVGUARD_AUTH_METHOD=systemd`.

## Rotating the Vault token

To replace the encrypted credential without stopping the service:

```bash
# Encrypt the new token
echo -n "hvs.YYYYYYYY" | \
    systemd-creds encrypt --name=vault-token - /etc/srvguard/vault-token.cred

# Restart so systemd decrypts the new file into $CREDENTIALS_DIRECTORY
systemctl restart srvguard-nginx.service
```

srvguard will re-authenticate with the new token on startup and continue
serving secrets to the child process.
