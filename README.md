# srvguard

> [!NOTE]
> **Early adopter preview — work in progress.**
> This project is publicly available to gather feedback during the design phase.
> The architecture and APIs are still evolving and are not yet ready for production use.
> If you are evaluating srvguard or have thoughts to share, please open a GitHub Discussion —
> we are keen to hear from early adopters. Pull requests are not being accepted at this stage.

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
[HCL Domino CertMgr](https://opensource.hcltechsw.com/domino-cert-manager/)
([docs](https://help.hcl-software.com/domino/14.5.1/admin/certificate_management_with_certmgr.html))
as the certificate lifecycle component. CertMgr owns the full TLS certificate
lifecycle — ACME flows with public and commercial CAs (Let's Encrypt, DigiCert,
Sectigo, Actalis and others), key generation and rollover, and automated
renewal. It can push issued certificates and keys into Vault, from where
`srvguard` delivers them to whatever process needs them.

For Domino specifically, CertMgr handles all TLS certificate management
natively. `srvguard`'s role in the Domino world is delivering non-certificate
secrets — `server.id` passwords, API keys — via the kernel keyring to the
Domino Extension Manager. The two tools are complementary, not overlapping.

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

| Variable               | Default               | Description                          |
|------------------------|-----------------------|--------------------------------------|
| `SRVGUARD_OUTPUT_MODE` | `files`               | Output backend: `files` or `keyring` |
| `SRVGUARD_OUTPUT_DIR`  | `/run/srvguard/certs` | Directory for the `files` backend    |

The keyring label is derived automatically from the build salt, the external secret
file, and the current boot ID — see [Keyring label derivation and build salt](#keyring-label-derivation-and-build-salt).

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

srvguard -- /opt/hcl/domino/bin/server
```

The Domino Extension Manager hook calls `SrvGuardDeriveKeyLabel()` at startup
to derive the opaque keyring label, then `SrvGuardKeyringRead()` to retrieve
the `server.id` password. The key is revoked immediately after the first read
— it cannot be read again.

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

// Derive the keyring label from build_salt || external_secret || boot_id.
// Must be called before SrvGuardKeyringRead / SrvGuardKeyringPeek.
// pszLabel must be at least 33 bytes.  Returns false if the external secret
// file cannot be read.
bool SrvGuardDeriveKeyLabel (char *pszLabel, size_t nLabelLen);

// Read a named field from the kernel keyring.
// The key is revoked immediately after reading — one-time use.
bool SrvGuardKeyringRead (const char *pszLabel,
                          const char *pszField,
                          char       *pszValue,
                          size_t      nMaxLen);

// Read a named field WITHOUT revoking the key.
// Use when the same key will be consumed again in a later call.
bool SrvGuardKeyringPeek (const char *pszLabel,
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

static char g_szKeyringLabel[33] = {0};

// Called once at extension manager initialisation.
// Derives the keyring label and — if SRVGUARD_PW_SETUP is set —
// sets the initial password on a passwordless server.id.
STATUS MainEntryPoint (void)
{
    char szIDFile[MAXPATH]   = {0};
    char szPassword[512]     = {0};
    STATUS err               = NOERROR;

    if (!SrvGuardDeriveKeyLabel (g_szKeyringLabel, sizeof (g_szKeyringLabel)))
    {
        printf ("srvguard: cannot derive keyring label\n");
        return ERR_MISC_INVALID_ARGS;
    }

    // initial setup — only when the ID has no password yet
    if (OSGetEnvironmentLong ("SRVGUARD_PW_SETUP"))
    {
        if (OSGetEnvironmentString ("KeyFilename", szIDFile, sizeof (szIDFile)) &&
            SrvGuardKeyringPeek (g_szKeyringLabel, "password", szPassword, sizeof (szPassword)))
        {
            err = SECKFMChangePassword (szIDFile, NULL, szPassword);
            if (!err)
                OSSetEnvironmentInt ("SRVGUARD_PW_SETUP", 0);
        }
        SrvGuardZero (szPassword, sizeof (szPassword));
    }

    return NOERROR;
}

// Called by Extension Manager before server.id is opened.
// No Domino C-API calls are safe at this stage — pure C only.
STATUS LNPUBLIC PasswordCallback (/* EM args */)
{
    char szPassword[512] = {0};

    if (!SrvGuardKeyringRead (g_szKeyringLabel, "password",
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

## Keyring label derivation and build salt

The Linux kernel keyring key is stored under a derived label rather than a
fixed string like `"srvguard"`.  The label is computed at runtime as:

```
label = hex( SHA256( build_salt || external_secret || boot_id ) )[:32]
```

**build_salt** — a 64-character hex string (32 bytes) baked into both the
`srvguard` binary and the `domsrvguard` consumer library at compile time.
It differentiates this deployment from any other build of srvguard.  It is
not a secret by itself — an attacker who extracts it from a binary still
cannot derive the label without the external secret.  The default value
shipped in the repository is freshly generated and is fine to use as-is.
To use a deployment-specific value, set `SRVGUARD_BUILD_SALT` at build time:

```bash
export SRVGUARD_BUILD_SALT=$(od -An -tx1 -N32 /dev/urandom | tr -d ' \n')
./compile.sh                                                    # srvguard binary
make SRVGUARD_BUILD_SALT=$SRVGUARD_BUILD_SALT -C consumers/cpp  # C++ library
```

Both commands must receive the **same value** — they are two halves of the
same trust anchor.

**external_secret** — 32 random bytes written to
`/var/lib/srvguard/keyring.secret` (mode 0400, owned by the service user)
by srvguard on first run.  This file never enters source control.  It is the
deployment-unique component that makes the label unguessable even if the
build salt is known.  Override the path with `SRVGUARD_KEYRING_SECRET_FILE`
for testing (the demo uses `/tmp/srvguard-keyring.secret`).

**boot_id** — `/proc/sys/kernel/random/boot_id`, a UUID that changes on every
reboot.  This ensures the label is different each time the machine starts,
so a key captured from a previous boot cannot be replayed.

The result is a 32-character opaque hex label that an attacker cannot predict
without access to both the binary (build salt) and the secret file, and even
then only for the current boot session.

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
- **Kernel keyring** backend stores secrets in the Linux user keyring
  (`KEY_SPEC_USER_KEYRING`), shared across all processes of the same UID.
  Keys are revoked on first read and exist only in kernel memory — never
  on disk or in the filesystem.  The key label is derived from a build salt,
  a machine-local secret file, and the current boot ID — it changes every
  reboot and is not guessable without both inputs.
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

## Credential Lifecycle

This section covers the full lifecycle of the systemd encrypted credential
file used by `SRVGUARD_AUTH_METHOD=systemd` — from first-time setup through
normal operation and eventual rotation.

### Bootstrap — first-time setup

Before the service can start, create the encrypted credential file:

```bash
srvguard --bootstrap [/path/to/vault-token.cred]
```

The command:
1. Prompts for the initial credential value (e.g. a Vault token), with echo suppressed
2. Encrypts it via `systemd-creds encrypt` — the result is protected by TPM2 (if
   available) or a machine-derived key and is unreadable on any other machine
3. Writes the encrypted file to `SRVGUARD_CRED_FILE` (default
   `/etc/srvguard/vault-token.cred`)
4. Prints the `LoadCredentialEncrypted=` directive to add to the unit file

The corresponding unit snippet:

```ini
[Service]
LoadCredentialEncrypted=vault-token:/etc/srvguard/vault-token.cred
Environment=SRVGUARD_AUTH_METHOD=systemd
```

### Normal operation

At each service start, systemd decrypts the `.cred` file using TPM2 or the
machine-derived key and writes the plaintext to a private tmpfs mount at
`$CREDENTIALS_DIRECTORY/vault-token`.  This directory is visible only to
processes in the service's own mount namespace — other services, including
the Domino server, cannot see it.

srvguard then:
1. Reads the plaintext credential from `$CREDENTIALS_DIRECTORY`
2. Authenticates to Vault and fetches secrets
3. Writes secrets to the configured output backend (keyring or files)
4. Starts and supervises the child process

Once srvguard has written secrets to the keyring and started the child process,
the credential file is no longer accessed.  The plaintext credential exists only
transiently in the service's private tmpfs namespace.

### Rotation

When a Vault token expires or the credential needs to be replaced:

```bash
srvguard --rotate [/path/to/vault-token.cred]
```

The command uses a **two-phase commit with in-memory rollback**:

| Step | Action |
|------|--------|
| 1. Read | Load current encrypted bytes from `.cred` into memory — this is the rollback copy |
| 2. Verify | Decrypt the current file to confirm this machine can read it before making changes |
| 3. Encrypt | Prompt for new value; run `systemd-creds encrypt` to `.cred.new` (temp file) |
| 4. Commit | Atomic `rename(.cred.new, .cred)` — both paths are on the same filesystem |
| 5. Apply | Restart the service: `systemctl restart <unit>` |

If the rename fails at step 4, the old encrypted bytes are written back from
memory — the original `.cred` is restored exactly as it was.  The rollback is
cost-free: reading the current credential is an inherent first step of any
rotation, so both old and new state are already in memory when the commit is
attempted.

The service continues running on the old credential until step 5 — there is
no window where neither credential is valid.  If the restart fails for an
unrelated reason, running `--rotate` again replaces the already-committed new
credential.

### Security properties of the .cred file

| Property | Details |
|----------|---------|
| At rest | Encrypted by TPM2 (if available) or machine-derived key — unreadable on another host |
| In service namespace | Decrypted by systemd to `$CREDENTIALS_DIRECTORY` (private tmpfs); inaccessible to other services |
| After srvguard starts | Vault token is consumed; secrets live only in the kernel keyring or a separate tmpfs |
| Root access | A root process can use `nsenter --mount` to access the service tmpfs, or read the `.cred` file from disk — the `.cred` file cannot be decrypted without TPM or matching machine-id |
| Cross-service visibility | The `.cred` file never appears in the Domino process namespace — srvguard runs as a separate oneshot service and delivers secrets via the user keyring instead |
