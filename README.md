# srvguard

**Nash!Com Service Guard** — a universal service launcher and secret manager
for secure, automated secret delivery to any workload.

> **TL;DR —** A statically compiled binary that authenticates to Vault (or reads a
> systemd credential), fetches secrets, and delivers them to any process —
> TLS certificates to NGINX, `server.id` passwords to Domino — without keys
> ever touching disk. Supports VM, container, and Kubernetes deployments using
> each platform's native identity mechanism.

`srvguard` solves a fundamental bootstrap problem: a service needs its
secrets (TLS certificate, private key, password) before it can start, but
those secrets live in a protected store that requires authentication to access.
The guard authenticates using the platform's native identity mechanism,
fetches the secrets, delivers them to the configured output backend, processes
any config templates, starts the managed service, and then continues to watch
for secret rotations — signalling the service to reload when they change.

Vault is the default secret store, but srvguard also works with systemd
credentials directly — no Vault required.

Designed to run as a statically compiled binary with no external dependencies.
Works in minimal containers such as
[Chainguard static](https://images.chainguard.dev/directory/image/static/overview)
where no shell or package manager is available.

## The Challenge in 2026

Two independent pressures are making manual secret management unsustainable.

**Certificate lifetimes are shrinking.** TLS certificate maximum lifetimes
dropped to 200 days in March 2026 and will reach 47 days by 2029. At that
renewal frequency, certificates need to be rotated roughly every six weeks —
and the private key with them. Manual processes that worked for two-year
certificates simply break down. Automation is no longer optional.

**Application secrets have no expiry model at all.** Domino `server.id`
passwords, API keys, database credentials, and signing keys sit in files,
scripts, and administrator memory. They are copied during deployments, stored
in backups, and rarely rotated. Every copy is a long-lived liability with no
built-in expiry and no audit trail.

`srvguard` can be part of the answer. It delivers any secret — TLS certificate,
private key, `server.id` password — from a protected source to the process
that needs it, using only what the platform already provides for trust. The full context
on certificate lifetimes and the Domino ecosystem is in
[Certificate Lifetimes Are Shrinking — Is Your Domino Infrastructure Ready?](docs/certificate-lifetime-reduction.md).

## Context and Architecture

`srvguard` is designed to fit into a larger certificate lifecycle and secret
distribution platform. One well-tested combination is
[HashiCorp Vault](https://www.vaultproject.io/) as the central secret store
together with
[HCL Domino CertMgr](https://help.hcl-software.com/domino/14.5.1/admin/secu_certmgr_overview.html)
as the certificate lifecycle component. CertMgr supports ACME flows with
public and commercial CAs (Let's Encrypt, DigiCert, Sectigo, Actalis and
others), handles key generation and rollover, and automates renewal. It can
push issued certificates and keys into Vault, from where `srvguard` delivers
them to whatever process needs them.

Other combinations work too — Vault's own PKI engine, an external ACME client
like `acme.sh`, or a plain file drop from any provisioning tool. `srvguard`
does not require any specific upstream.

**CertMgr** is purpose-built for certificate lifecycle management and CA interaction.

| CertMgr capability          | Notes                                                |
|-----------------------------|------------------------------------------------------|
| ACME certificate lifecycle  | Let's Encrypt, DigiCert, Sectigo, Actalis and others |
| Key generation and rollover | Private key never leaves the Domino server           |
| Push cert + key → Vault     | Central distribution for non-Domino consumers        |
| Push → Kubernetes Secrets   | Containerised workloads                              |

**Vault** is purpose-built for secret storage, access policy, and audit.

| Vault distribution path      | Consumer                 | Notes                                   |
|------------------------------|--------------------------|------------------------------------------|
| srvguard → files backend     | NGINX, any service       | TLS cert + key on tmpfs                  |
| srvguard → kernel keyring    | Domino Extension Manager | `server.id` password, never on disk      |
| Vault Agent                  | Legacy systems           | Vault-native agent for other workloads   |
| Vault PKI + ACME             | Internal CAs             | No CertMgr needed for internal issuance  |
| SSH signing, dynamic secrets | Any                      | Other standard Vault use cases           |

**srvguard** is the last mile — a thin, dependency-free binary that bridges
the secret store to any process, in any container, on any platform.

## How It Works

```
srvguard starts
  │
  ├── 1. Authenticate to Vault (file / systemd / k8s / cert)
  ├── 2. Fetch secret from KV v2
  ├── 3. Write secret to output backend (files or kernel keyring)
  ├── 4. Process config template: nginx.conf.template → nginx.conf
  ├── 5. Start managed service (e.g. nginx -g "daemon off;")
  │
  └── loop every SRVGUARD_POLL_INTERVAL
        ├── check KV v2 metadata version (cheap — no secret data fetched)
        ├── on version change:
        │     fetch new secret → write to backend → signal service
        └── on Vault auth error → re-authenticate and retry
```

The managed service is started **after** secrets are in place and config is
rendered — no race condition on startup. On secret rotation the service
receives a configurable signal (default `SIGHUP`) to reload without downtime.

## Authentication Methods

`srvguard` supports three authentication paths. Select with
`SRVGUARD_AUTH_METHOD` (default: `file`).

| Method    | Identity source                       | When to use                        |
|-----------|---------------------------------------|------------------------------------|
| `file`    | `role_id` + `secret_id` files on disk | Default — containers, any platform |
| `systemd` | `$CREDENTIALS_DIRECTORY/<cred>`       | VMs with systemd v250+             |
| `k8s`     | Kubernetes service account JWT        | Pods running in Kubernetes         |
| `cert`    | Machine-encrypted PKI client cert     | VMs/bare metal without systemd     |

> `approle` is accepted as an alias for `file`.

### File credentials (default)

Reads `role_id` and `secret_id` from files at the paths configured by
`SRVGUARD_ROLE_ID_FILE` and `SRVGUARD_SECRET_ID_FILE`. No additional
configuration required. The files are typically placed on a tmpfs bind-mount
by the host or orchestrator.

### mTLS cert auth

On first start, reads a one-time Vault response-wrapping token from
`SRVGUARD_WRAP_TOKEN_FILE`, calls `/v1/sys/wrapping/unwrap` to retrieve a
PKI-issued client certificate and key, encrypts the bundle with a key derived
from `/etc/machine-id`, and persists it to `SRVGUARD_CLIENT_ENC_FILE`. On
subsequent starts the bundle is decrypted directly — no wrap token needed.

Set `SRVGUARD_AUTH_METHOD=cert`. See [Secret Distribution Across Platforms — VM, Container, and Kubernetes](docs/architecture.md)
for the full auth model including the mTLS bootstrap flow.

### Kubernetes service account (k8s)

Reads the Pod's service account JWT from `SRVGUARD_K8S_TOKEN_FILE` (standard
Kubernetes mount path by default) and authenticates to Vault's Kubernetes auth
method. The JWT is issued and rotated by the kubelet — no credential files or
operator bootstrap per Pod.

Set `SRVGUARD_AUTH_METHOD=k8s` and `SRVGUARD_K8S_ROLE=<role>`. The Vault-side
setup (one time per cluster) is in the nsh-vault-deploy provisioner.

### systemd credential auth

Reads a pre-issued Vault token from
`$CREDENTIALS_DIRECTORY/$SRVGUARD_SYSTEMD_CRED` (default credential name:
`vault-token`). systemd decrypts the credential using TPM2 or a machine-bound
key before the service starts — no crypto in srvguard is required for this
path.

Set `SRVGUARD_AUTH_METHOD=systemd`. Example unit snippet:

```ini
[Service]
LoadCredentialEncrypted=vault-token:/etc/srvguard/vault-token.cred
Environment=SRVGUARD_AUTH_METHOD=systemd
```

See [systemd Credentials](docs/systemd-credentials.md) for background
on how systemd credentials work and security properties.


## Output Backends

### files
Writes secrets as individual files to a directory (typically a `tmpfs` mount
so they never touch persistent storage):

| File           | Content                                       |
|----------------|-----------------------------------------------|
| `server.crt`   | Certificate chain (`chain` field)             |
| `server.key`   | Encrypted private key (`encrypted_key` field) |
| `ssl.password` | Key password (`key_password` field)           |

Used for: NGINX, Apache, any service that reads credentials from files.

### keyring
Stores the full secret payload as JSON in the Linux kernel session keyring
under a named label. The consumer process reads the key and **immediately
revokes it** — it exists in kernel memory only, never on disk.

Used for: native applications that can call `keyctl` directly, such as a
Domino Extension Manager hook that reads the `server.id` password at startup.

See [Linux Kernel Keyring](docs/linux-kernel-keyring.md) for background
on the kernel keyring facility, security properties, and the read-once-revoke
pattern.

## Configuration

All configuration is via environment variables prefixed `SRVGUARD_`.

### Vault Connection

| Variable                  | Default                    | Description                               |
|---------------------------|----------------------------|-------------------------------------------|
| `SRVGUARD_ADDR`           | `https://127.0.0.1:8200`   | Vault server URL                          |
| `SRVGUARD_ROLE_ID_FILE`   | `/etc/srvguard/role_id`    | Path to `role_id` file (file auth mode)   |
| `SRVGUARD_SECRET_ID_FILE` | `/etc/srvguard/secret_id`  | Path to `secret_id` file (file auth mode) |
| `SRVGUARD_CACERT`         | `/etc/srvguard/cacert.pem` | CA certificate for Vault TLS verification |

### Secret Path

The KV v2 secret path follows the convention `{mount}/data/certs/{fqdn}/{type}`
and is built automatically from three variables:

| Variable                | Default             | Description                                         |
|-------------------------|---------------------|-----------------------------------------------------|
| `SRVGUARD_SECRET_MOUNT` | `secret`            | KV v2 mount point                                   |
| `SRVGUARD_SECRET_FQDN`  | *(system hostname)* | Server FQDN — the primary identifier for the secret |
| `SRVGUARD_SECRET_TYPE`  | `tls`               | Secret type: `tls`, `rsa`, or `ecdsa`               |

For example, with `SRVGUARD_SECRET_FQDN=myserver.example.com` and
`SRVGUARD_SECRET_TYPE=rsa` the resolved path is:

```
secret/data/certs/myserver.example.com/rsa
```

Use `SRVGUARD_SECRET_PATH` to override the full path directly when the
standard convention does not apply:

| Variable               | Default   | Description                                              |
|------------------------|-----------|----------------------------------------------------------|
| `SRVGUARD_SECRET_PATH` | *(unset)* | Full KV v2 path override — takes priority over the above |

> **Container note:** set `hostname: myserver.example.com` in
> `docker-compose.yml` and `SRVGUARD_SECRET_FQDN` is resolved automatically
> from the container hostname — no extra configuration needed.

### Output

| Variable                 | Default               | Description                          |
|--------------------------|-----------------------|--------------------------------------|
| `SRVGUARD_OUTPUT_MODE`   | `files`               | Output backend: `files` or `keyring` |
| `SRVGUARD_OUTPUT_DIR`    | `/run/srvguard/certs` | Directory for the `files` backend    |
| `SRVGUARD_KEYRING_LABEL` | `srvguard`            | Key label for the `keyring` backend  |

### Config Template Processing

`srvguard` can process a configuration file template before starting the
managed service, replacing `${VAR}` and `$VAR` placeholders with environment
variable values. This removes the need for the `envsubst` binary or a shell
in minimal containers.

| Variable                | Default   | Description                                                          |
|-------------------------|-----------|----------------------------------------------------------------------|
| `SRVGUARD_TEMPLATE_SRC` | *(unset)* | Path to the template file, e.g. `/etc/srvguard/nginx.conf.template` |
| `SRVGUARD_TEMPLATE_DST` | *(unset)* | Path to write the rendered config, e.g. `/etc/nginx/nginx.conf`     |

Template processing is skipped if either variable is not set.

Any environment variable can be referenced in the template:

```nginx
server_name ${NGINX_SERVER_NAME};
ssl_certificate ${SRVGUARD_OUTPUT_DIR}/server.crt;
```

See `examples/nginx/nginx.conf.template` for a complete example.

### Process Supervision

| Variable                    | Default   | Description                                                                                   |
|-----------------------------|-----------|-----------------------------------------------------------------------------------------------|
| `SRVGUARD_POLL_INTERVAL`    | `60s`     | How often to check for secret version changes. Accepts Go duration strings: `30s`, `5m`, `1h` |
| `SRVGUARD_RELOAD_CONTAINER` | *(unset)* | Docker container name to signal on secret rotation (sidecar mode)                             |

The managed service command is passed after `--` on the command line:

```bash
srvguard -- nginx -g "daemon off;"
```

If no command is given, `srvguard` runs in **secret-only mode** — it
fetches and writes secrets but does not manage a process. Useful when paired
with `SRVGUARD_RELOAD_CONTAINER` to signal a sibling container.

## Credential Files

Credentials are read from files, not environment variables, to avoid
exposure via `/proc/<pid>/environ`.

```
/etc/srvguard/
  role_id                  — file auth: role_id         (mode 0644)
  secret_id                — file auth: secret_id       (mode 0600)
  cacert.pem               — CA certificate for Vault TLS
  nginx.conf.template      — optional config template
```

Mount this directory read-only into the container. The only file that needs
to be writable is the rendered config output (`SRVGUARD_TEMPLATE_DST`), which
lives outside this directory.

## Deployment Modes

### Mode 1 — Direct process management

`srvguard` runs as PID 1 in the container, fetches secrets, renders
config, and launches the service as a child process. Signals the child
directly on rotation.

```
Container
  srvguard (PID 1)
    └── nginx (child)
```

```bash
srvguard -- nginx -g "daemon off;"
```

### Mode 2 — Sidecar container

`srvguard` runs as a sidecar alongside the service container. Secrets
are shared via a tmpfs volume. On rotation, srvguard signals the service
container via the Docker socket.

```
docker-compose
  srvguard container ──tmpfs──► nginx container
        │
        └── docker kill --signal=HUP nginx
```

```yaml
SRVGUARD_RELOAD_CONTAINER: "nginx"
```

### Mode 3 — Host process

`srvguard` runs on the host outside any container, writes secrets to a
tmpfs that is mounted into the service container. The host process has direct
Docker socket access and full OS permissions. The service container has zero
Vault access.

```
Host
  srvguard ──tmpfs──► nginx container (read-only mount)
      │
      └── docker kill --signal=HUP nginx
```

This is the most secure deployment — the container is completely isolated
from Vault credentials.

## Usage Examples

### NGINX — direct process management

```bash
export SRVGUARD_ADDR=https://vault.example.com:8200
export SRVGUARD_SECRET_PATH=secret/data/certs/nginx.example.com/tls
export SRVGUARD_OUTPUT_DIR=/run/srvguard/certs
export SRVGUARD_TEMPLATE_SRC=/etc/srvguard/nginx.conf.template
export SRVGUARD_TEMPLATE_DST=/etc/nginx/nginx.conf
export NGINX_SERVER_NAME=nginx.example.com

srvguard -- nginx -g "daemon off;"
```

### NGINX — sidecar with Docker compose

See `docker-compose.yml` for a complete working model. Key points:

- `certs` volume is a tmpfs shared between `srvguard` and `nginx`
- `nginx-config` volume is shared for the rendered `nginx.conf`
- Docker socket is mounted for SIGHUP signalling
- `nginx.conf.template` is placed in the `credentials` bind mount

### Domino — server.id password via kernel keyring

```bash
export SRVGUARD_SECRET_PATH=secret/data/domino/server01.example.com/id
export SRVGUARD_OUTPUT_MODE=keyring
export SRVGUARD_KEYRING_LABEL=srvguard

srvguard -- /opt/hcl/domino/bin/server
```

The Domino Extension Manager hook calls `SrvGuardKeyringRead()` at startup
to retrieve the `server.id` password. The key is revoked immediately after
the first read — it cannot be read again.

### Secret-only mode

Fetches and writes secrets without managing a process. Combined with
`SRVGUARD_RELOAD_CONTAINER` to signal a separately managed service:

```bash
export SRVGUARD_SECRET_PATH=secret/data/certs/myservice/tls
export SRVGUARD_OUTPUT_DIR=/run/srvguard/certs
export SRVGUARD_RELOAD_CONTAINER=myservice

srvguard
```

## C++ Consumer

The `consumers/cpp/` directory contains a small library for native
applications that need to read secrets written by `srvguard`. No Vault
dependency, no curl, no external libraries required.

### API

```cpp
#include "srvguard.hpp"

// Read a named field from the kernel keyring.
// The key is revoked immediately after reading — one-time use.
bool SrvGuardKeyringRead (const char *pszLabel,
                          const char *pszField,
                          char       *pszValue,
                          size_t      nMaxLen);

// Read a file written by the files backend.
bool SrvGuardFileRead (const char *pszDir,
                       const char *pszFile,
                       char       *pszValue,
                       size_t      nMaxLen);

// Overwrite a buffer with zeros — call after consuming a secret.
// Uses volatile writes to prevent compiler optimisation.
void SrvGuardZero (void *pBuf, size_t nLen);
```

### Domino EM Hook Example

```cpp
#include "srvguard.hpp"

// Called by Extension Manager before server.id is opened.
// No Domino C-API calls are safe at this stage — pure C only.
STATUS LNPUBLIC PasswordCallback (/* EM args */)
{
    char szPassword[512] = {};

    if (!SrvGuardKeyringRead ("srvguard", "password",
                               szPassword, sizeof (szPassword)))
        return ERR_EM_CONTINUE; // key not found — let Domino prompt

    // pass szPassword to Domino password mechanism ...

    SrvGuardZero (szPassword, sizeof (szPassword));
    return NOERROR;
}
```

### Build

```bash
cd consumers/cpp
make
```

Produces `libsrvguard.a` for static linking into any native application.

## Building srvguard

Use `compile.sh` — output always lands in `bin/`.

### Native (requires Go)

```bash
./compile.sh              # current platform → bin/srvguard
./compile.sh -amd64       # → bin/srvguard-linux-amd64
./compile.sh -arm64       # → bin/srvguard-linux-arm64
./compile.sh -all         # both amd64 + arm64
```

### Without Go — build inside a container

```bash
./compile.sh -docker      # uses golang:alpine, no local Go required
```

Output is written to `bin/srvguard` on the host via a volume mount.
Override the image with `GO_IMAGE=golang:1.22-alpine ./compile.sh -docker`.

### Container image (Docker)

```bash
./build.sh                # release image, local platform → docker load
./build.sh -docker test   # test image
REGISTRY=myregistry.example.com/srvguard ./build.sh push   # multi-arch push
```

## Vault Secret Format

`srvguard` expects a flat KV v2 secret. Field names are flexible —
configure the consumer to read whichever fields are present. The defaults
used by [nsh-vault-deploy](https://github.com/nashcom/nsh-vault-deploy) are:

**TLS credentials:**

| Field           | Content                                          |
|-----------------|--------------------------------------------------|
| `chain`         | PEM certificate chain (leaf + intermediates)     |
| `encrypted_key` | PEM private key, encrypted with `key_password`   |
| `key_password`  | Password protecting the private key              |
| `cn`            | Common name (informational)                      |
| `not_after`     | Certificate expiry date used to schedule renewal |

**Simple password (e.g. Domino server.id):**

| Field      | Content            |
|------------|--------------------|
| `password` | The password value |

## Security Notes

- **File credentials** (`role_id`, `secret_id`) are read from files at
  `/etc/srvguard/`, not from environment variables, to prevent exposure
  via `/proc/<pid>/environ`.
- **Kernel keyring** backend stores secrets in the Linux session keyring.
  Keys are revoked on first read and exist only in kernel memory — never
  on disk or in the filesystem.
  → [Linux Kernel Keyring](docs/linux-kernel-keyring.md)
- **systemd credentials** are decrypted by the service manager using TPM2 or
  a machine-bound key before srvguard starts. The plaintext lives in
  `$CREDENTIALS_DIRECTORY` on a tmpfs and is inaccessible to other services.
  → [systemd Credentials](docs/systemd-credentials.md)
- **mTLS client cert** bundle is encrypted with a key derived from
  `/etc/machine-id` (HKDF-SHA256 + AES-256-GCM). Useless on any other machine.
- **Files backend** should always target a `tmpfs` mount. The provided
  `docker-compose.yml` configures the shared `certs` volume as tmpfs.
- **Config templates** are rendered to the destination path with mode `0644`.
  If the destination contains sensitive values, adjust permissions after
  rendering or use the keyring backend instead.
- **Token renewal**: on any Vault API failure during the poll loop,
  `srvguard` re-authenticates automatically using the credential files.
- **`SrvGuardZero()`** uses a `volatile` write loop to prevent the compiler
  from optimising away memory clears on secret buffers.
- **Sidecar Docker socket** access is required only for Mode 2. In Mode 3
  (host process) the socket stays on the host. In Mode 1 (direct child)
  no socket access is needed at all.

See [Secret Distribution Across Platforms](docs/architecture.md) for the full
runtime identity model covering VMs, containers, and Kubernetes.
