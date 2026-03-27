# srvguard

**Nash!Com Service Guard** — a universal service launcher and secret manager
for [HashiCorp Vault](https://www.vaultproject.io/)-integrated workloads.

`srvguard` solves a fundamental bootstrap problem: a service needs its
secrets (TLS certificate, private key, password) before it can start, but the
secrets live in Vault which requires authentication to access. The guard
authenticates to Vault, fetches the secrets, delivers them to the configured
output backend, processes any config templates, starts the managed service,
and then continues to watch for secret rotations — signalling the service to
reload when they change.

Designed to run as a statically compiled binary with no external dependencies.
Works in minimal containers such as
[Chainguard static](https://images.chainguard.dev/directory/image/static/overview)
where no shell or package manager is available.

## Background

TLS certificate maximum lifetimes are shrinking — **200 days as of March 2026,
47 days by 2029**. At that frequency, manual certificate management breaks down.
Automation is no longer optional, and key rotation on every renewal cycle
becomes mandatory for meaningful security benefit.

`srvguard` is part of the answer to that problem for Domino and NGINX
infrastructure. The full story, including the CA/Browser Forum timeline,
the key rotation challenge, and how HCL Domino CertMgr and HashiCorp Vault
fit together, is in
[Certificate Lifetimes Are Shrinking — Is Your Domino Infrastructure Ready?](docs/certificate-lifetime-reduction.md).

## Context and Architecture

`srvguard` is part of a larger certificate lifecycle and secret distribution
platform built around [HashiCorp Vault](https://www.vaultproject.io/) as the
central distribution point.

[HCL Domino CertMgr](https://help.hcl-software.com/domino/14.0.0/admin/secu_certmgr_overview.html)
acts as the authoritative source for certificate lifecycle management —
handling ACME flows with public and commercial CAs (Let's Encrypt, DigiCert,
Sectigo, Actalis and others), key generation and rollover, and renewal
automation. Once a certificate is issued or renewed, CertMgr pushes it into
Vault. From there, `srvguard` handles the last mile: delivering secrets
securely to whatever process needs them.

```
CertMgr (HCL Domino)
  ├── manages cert lifecycle (ACME, Let's Encrypt, DigiCert, Sectigo ...)
  ├── pushes certificates and keys → Vault  (central distribution)
  └── pushes to K8s Secrets                 (containerized workloads)

Vault (HashiCorp)
  ├── srvguard ──────────────────────────→  NGINX, any service (files backend)
  ├── srvguard ──────────────────────────→  Domino EM hook    (kernel keyring)
  ├── Vault Agent ────────────────────────→  legacy systems
  ├── Vault PKI + ACME ───────────────────→  internal CAs (no CertMgr needed)
  └── SSH signing, dynamic secrets, ...     (other Vault use cases)
```

**CertMgr** stays the expert on certificates and CA interaction.
**Vault** stays the expert on secret storage and distribution policy.
**srvguard** is the last mile — a thin, dependency-free binary that bridges
Vault to any process, in any container, on any platform.

## How It Works

```
srvguard starts
  │
  ├── 1. Authenticate to Vault via AppRole
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

## Output Backends

### files
Writes secrets as individual files to a directory (typically a `tmpfs` mount
so they never touch persistent storage):

| File | Content |
|---|---|
| `server.crt` | Certificate chain (`chain` field) |
| `server.key` | Encrypted private key (`encrypted_key` field) |
| `ssl.password` | Key password (`key_password` field) |

Used for: NGINX, Apache, any service that reads credentials from files.

### keyring
Stores the full secret payload as JSON in the
[Linux kernel session keyring](https://www.man7.org/linux/man-pages/man7/keyrings.7.html)
under a named label. The consumer process reads the key and **immediately
revokes it** — it exists in kernel memory only, never on disk.

Used for: native applications that can call `keyctl` directly, such as a
Domino Extension Manager hook that reads the `server.id` password at startup.

## Configuration

All configuration is via environment variables prefixed `SRVGUARD_`.

### Vault Connection

| Variable | Default | Description |
|---|---|---|
| `SRVGUARD_ADDR` | `https://127.0.0.1:8200` | Vault server URL |
| `SRVGUARD_ROLE_ID_FILE` | `/etc/srvguard/role_id` | Path to file containing AppRole `role_id` |
| `SRVGUARD_SECRET_ID_FILE` | `/etc/srvguard/secret_id` | Path to file containing AppRole `secret_id` |
| `SRVGUARD_CACERT` | `/etc/srvguard/cacert.pem` | CA certificate for Vault TLS verification |

### Secret Path

The KV v2 secret path follows the convention `{mount}/data/certs/{fqdn}/{type}`
and is built automatically from three variables:

| Variable | Default | Description |
|---|---|---|
| `SRVGUARD_SECRET_MOUNT` | `secret` | KV v2 mount point |
| `SRVGUARD_SECRET_FQDN` | *(system hostname)* | Server FQDN — the primary identifier for the secret |
| `SRVGUARD_SECRET_TYPE` | `tls` | Secret type: `tls`, `rsa`, or `ecdsa` |

For example, with `SRVGUARD_SECRET_FQDN=myserver.example.com` and
`SRVGUARD_SECRET_TYPE=rsa` the resolved path is:

```
secret/data/certs/myserver.example.com/rsa
```

Use `SRVGUARD_SECRET_PATH` to override the full path directly when the
standard convention does not apply:

| Variable | Default | Description |
|---|---|---|
| `SRVGUARD_SECRET_PATH` | *(unset)* | Full KV v2 path override — takes priority over the above |

> **Container note:** set `hostname: myserver.example.com` in
> `docker-compose.yml` and `SRVGUARD_SECRET_FQDN` is resolved automatically
> from the container hostname — no extra configuration needed.

### Output

| Variable | Default | Description |
|---|---|---|
| `SRVGUARD_OUTPUT_MODE` | `files` | Output backend: `files` or `keyring` |
| `SRVGUARD_OUTPUT_DIR` | `/run/srvguard/certs` | Directory for the `files` backend |
| `SRVGUARD_KEYRING_LABEL` | `srvguard` | Key label for the `keyring` backend |

### Config Template Processing

`srvguard` can process a configuration file template before starting the
managed service, replacing `${VAR}` and `$VAR` placeholders with environment
variable values. This removes the need for the `envsubst` binary or a shell
in minimal containers.

| Variable | Default | Description |
|---|---|---|
| `SRVGUARD_TEMPLATE_SRC` | *(unset)* | Path to the template file, e.g. `/etc/srvguard/nginx.conf.template` |
| `SRVGUARD_TEMPLATE_DST` | *(unset)* | Path to write the rendered config, e.g. `/etc/nginx/nginx.conf` |

Template processing is skipped if either variable is not set.

Any environment variable can be referenced in the template:

```nginx
server_name ${NGINX_SERVER_NAME};
ssl_certificate ${SRVGUARD_OUTPUT_DIR}/server.crt;
```

See `examples/nginx/nginx.conf.template` for a complete example.

### Process Supervision

| Variable | Default | Description |
|---|---|---|
| `SRVGUARD_POLL_INTERVAL` | `60s` | How often to check for secret version changes. Accepts Go duration strings: `30s`, `5m`, `1h` |
| `SRVGUARD_RELOAD_CONTAINER` | *(unset)* | Docker container name to signal on secret rotation (sidecar mode) |

The managed service command is passed after `--` on the command line:

```bash
srvguard -- nginx -g "daemon off;"
```

If no command is given, `srvguard` runs in **secret-only mode** — it
fetches and writes secrets but does not manage a process. Useful when paired
with `SRVGUARD_RELOAD_CONTAINER` to signal a sibling container.

## Credential Files

AppRole credentials are read from files, not environment variables, to avoid
exposure via `/proc/<pid>/environ`.

```
/etc/srvguard/
  role_id                  — AppRole role_id            (mode 0644)
  secret_id                — AppRole secret_id          (mode 0600)
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

### Development binary

```bash
go build -o srvguard .
```

### Production static binary

```bash
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o srvguard .
```

### Container — test image (Wolfi runtime)

```bash
docker build --target test -t srvguard:test .
```

### Container — release image (Chainguard static)

```bash
docker build --target release -t srvguard:latest .
```

## Vault Secret Format

`srvguard` expects a flat KV v2 secret. Field names are flexible —
configure the consumer to read whichever fields are present. The defaults
used by [nashcom-vault](https://github.com/nashcom/nashcom-vault) are:

**TLS credentials:**

| Field | Content |
|---|---|
| `chain` | PEM certificate chain (leaf + intermediates) |
| `encrypted_key` | PEM private key, encrypted with `key_password` |
| `key_password` | Password protecting the private key |
| `cn` | Common name (informational) |
| `not_after` | Certificate expiry date used to schedule renewal |

**Simple password (e.g. Domino server.id):**

| Field | Content |
|---|---|
| `password` | The password value |

## Security Notes

- **AppRole credentials** are read from files at `/etc/srvguard/`, not
  from environment variables, to prevent exposure via `/proc/<pid>/environ`.
- **Kernel keyring** backend stores secrets in the Linux session keyring.
  Keys are revoked on first read and exist only in kernel memory — never
  on disk or in the filesystem.
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
