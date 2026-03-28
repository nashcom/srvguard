# Secret Distribution Across Platforms — VM, Container, and Kubernetes

## The Core Pattern

Every platform already provides a way to establish identity. srvguard uses
those existing mechanisms instead of inventing new ones.

```
platform identity → authentication → short-lived credentials → application
```

The result is a consistent operational model across three deployment modes.
No custom trust infrastructure is required on any path.

---

## Mode 1 — VM (systemd)

`SRVGUARD_AUTH_METHOD=systemd`

VMs are where most Domino and NGINX infrastructure runs today. The OS itself
provides the trust mechanism via `systemd` credentials.

`systemd` (v250+) supports `LoadCredentialEncrypted=` directives in unit
files. Before the service starts, systemd decrypts the named credential using
the machine's TPM2 binding or a machine-derived key and places the plaintext
in `$CREDENTIALS_DIRECTORY` — a tmpfs path scoped to that service alone.

```
operator                 systemd                   srvguard            Vault
   │                        │                         │                  │
   │  systemd-creds encrypt  │                         │                  │
   │  → vault-token.cred     │                         │                  │
   │────────────────────────►│                         │                  │
   │                         │  service start          │                  │
   │                         │  decrypt → tmpfs        │                  │
   │                         │────────────────────────►│                  │
   │                         │                         │  GET /v1/secret/ │
   │                         │                         │─────────────────►│
   │                         │◄─────────────────────────────────────────── │
   │                         │                         │  write to tmpfs  │
   │                         │                         │  signal service  │
```

**Unit file snippet:**
```ini
[Service]
LoadCredentialEncrypted=vault-token:/etc/srvguard/vault-token.cred
Environment=SRVGUARD_AUTH_METHOD=systemd
```

**Security properties:**
- Credential encrypted at rest; useless on any other machine
- Plaintext lives in memory only (`$CREDENTIALS_DIRECTORY` is tmpfs)
- Scoped to the service — inaccessible to other processes on the same host
- No additional daemon or sidecar required

**Standalone operation — no Vault needed:**
When the secret is simple enough (e.g. a Domino `server.id` password), the
systemd credential can be the secret itself. srvguard reads it and delivers it
to the application via the Linux kernel keyring — no Vault, no network:

```
systemd credential → srvguard → Linux kernel keyring → application
```

See [systemd Credentials](systemd-credentials.md) and the
[Linux Kernel Keyring](linux-kernel-keyring.md) for details on these
platform components.

*Trust establishment:* run `systemd-creds encrypt` during provisioning to
produce a `.cred` file. Deploy it to `/etc/srvguard/` on the target host.
One-time operation per host.

---

## Mode 2 — Container (credential file)

`SRVGUARD_AUTH_METHOD=file`

Containers have no native identity mechanism. Identity is provided by the
layer below — the host. The host places credential files on a tmpfs
bind-mount before the container starts. Inside the container, srvguard reads
them as ordinary files. It does not matter how they got there.

```
Host (Mode 1 VM or provisioning tool)     Container
  writes role_id + secret_id                srvguard (PID 1)
  → /run/srvguard-creds/ (tmpfs)              │
  ──────────── bind mount ──────────────────► │
                                              │  AppRole login → Vault
                                              │  write cert to tmpfs
                                              │  render nginx.conf
                                              │  start nginx
```

This is the default mode. No additional configuration is required beyond
pointing `SRVGUARD_ROLE_ID_FILE` and `SRVGUARD_SECRET_ID_FILE` at the
mounted paths.

**The same binary, two roles on the same host:**
srvguard runs on the VM host to provision the credential mount (Mode 1) and
again inside the container to consume it (Mode 2). The host does not know
what runs in the container; the container does not know where the credential
came from. They communicate through a file on a mount — the simplest possible
interface.

*Trust establishment:* write `role_id` and `secret_id` scoped to the
container's FQDN/role to the bind-mount path before the container starts.
A compromised container can only access its own secret path.

---

## Mode 3 — Kubernetes

`SRVGUARD_AUTH_METHOD=k8s`

Kubernetes is architecturally different from Modes 1 and 2. Identity is
native to the platform and requires no host-level provisioning or credential
files of any kind.

Every Pod automatically receives a signed service account JWT at a standard
path. The kubelet rotates it automatically. Vault validates the JWT by calling
the Kubernetes API server. No operator action is needed per Pod.

```
Kubernetes API server         Pod (srvguard)               Vault
       │                            │                         │
       │  issue + rotate JWT        │                         │
       │──────────────────────────► │                         │
       │                            │  POST /auth/k8s/login   │
       │                            │  { jwt, role }          │
       │                            │────────────────────────►│
       │◄─────────────────────────────── validate JWT ────────│
       │                            │◄────────────────────────│
       │                            │  Vault token            │
       │                            │  GET /v1/secret/...     │
       │                            │────────────────────────►│
```

**Configuration:**
```bash
SRVGUARD_AUTH_METHOD=k8s
SRVGUARD_K8S_ROLE=srvguard          # Vault role bound to the service account
# SRVGUARD_K8S_AUTH_MOUNT=kubernetes  # default
# SRVGUARD_K8S_TOKEN_FILE=/var/run/secrets/kubernetes.io/serviceaccount/token
```

No bootstrap secret is required. Identity is short-lived and
platform-managed. This is the most operationally simple model at scale.

*Trust establishment (once per cluster):*
```bash
vault auth enable kubernetes
vault write auth/kubernetes/config \
  kubernetes_host=https://$KUBERNETES_PORT_443_TCP_ADDR:443
vault write auth/kubernetes/role/srvguard \
  bound_service_account_names=srvguard \
  bound_service_account_namespaces=default \
  policies=srvguard-policy \
  ttl=1h
```

See the nsh-vault-deploy provisioner for the full setup.

---

## Combined — VM Host + Containers (Mode 1 + Mode 2)

In a typical server deployment, Modes 1 and 2 work together on the same
host. The VM layer manages trust; the container layer consumes secrets.
srvguard runs in both roles — the same binary, different configuration.

```
VM host
├── srvguard (systemd service — Mode 1)
│     reads $CREDENTIALS_DIRECTORY/vault-token
│     authenticates to Vault
│     writes role_id + secret_id → /run/srvguard-creds/ (tmpfs)
│
├── /run/srvguard-creds/  ← tmpfs bind-mount
│
└── Container (nginx)
      └── srvguard (PID 1 — Mode 2)
            reads /run/srvguard-creds/role_id + secret_id
            authenticates to Vault
            fetches cert + key → /run/certs/ (tmpfs)
            renders nginx.conf from template
            starts nginx
            signals nginx on cert rotation
```

The container has no direct Vault credentials of its own. It inherits
the right to authenticate from what the host placed on the mount. If the
container is compromised, the attacker holds `role_id` and `secret_id`
scoped to that container's path — nothing else. The host-side Vault token
never enters the container.

This separation also means the container image needs no secret baked in.
The same image runs in dev, staging, and production — only the mount content
differs.

---

## Auth Method Summary

| Mode | `SRVGUARD_AUTH_METHOD` | Identity source |
|---|---|---|
| VM (systemd) | `systemd` | `$CREDENTIALS_DIRECTORY/<cred>` — token used directly |
| Container (file) | `file` | `role_id` + `secret_id` files on bind-mount |
| Kubernetes | `k8s` | Service account JWT at standard K8s path |
| mTLS (fallback) | `cert` | Machine-encrypted PKI client cert (`client.enc`) |

> `approle` is accepted as an alias for `file` for backward compatibility.

---

## Design Principles

**Use existing trust mechanisms.**
systemd credentials, Kubernetes service accounts, and machine-id derivation
are platform primitives. srvguard adapts to them — it does not replace them.

**Separate identity from credentials.**
Platform identity proves who you are. Vault tokens and mTLS certificates
prove you are still authorised right now.

**Prefer short-lived credentials.**
Vault tokens and mTLS certificates should have bounded TTLs. Long-lived
credentials are only acceptable for bootstrap.

**Minimise persistent secrets.**
Use memory-backed storage: `tmpfs`, kernel keyring, `$CREDENTIALS_DIRECTORY`.
Where persistence is unavoidable (e.g. `client.enc` for mTLS), encrypt with
a machine-scoped key.

**Make the bootstrap explicit.**
Each environment defines how initial trust is established. The bootstrap path
is a deliberate operator action, separate from the steady-state path.

**One binary, multiple roles.**
The same `srvguard` binary runs as a host-side credential delivery service
(Mode 1) and as an in-container application wrapper (Mode 2). Configuration
determines the role.

---

## Relationship to Other Components

| Component | Role |
|---|---|
| **HashiCorp Vault** | Secret store, PKI, audit log, policy enforcement |
| **CertMgr (Domino)** | ACME client — manages Domino TLS certs, pushes to Vault after issuance |
| **srvguard** | Fetches secrets from Vault (or platform), delivers to applications |
| **systemd** | Encrypts and injects credentials on VM/bare-metal |
| **Kubernetes** | Provides service account JWT, rotates automatically |
| **NGINX / Domino** | Consuming applications — reload triggered on secret rotation |

See [nsh-vault-deploy](https://github.com/nashcom/nsh-vault-deploy) for the
Vault server configuration, provisioner scripts, and CertMgr integration.
