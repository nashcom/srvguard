# Certificate Lifetimes Are Shrinking — Is Your Domino Infrastructure Ready?

*by Nash!Com*

> **TL;DR —** Certificate maximum lifetimes dropped to 200 days in March 2026
> and will reach 47 days by 2029. At that frequency, manual renewal becomes
> operationally impossible. HCL Domino CertMgr automates issuance and renewal
> end-to-end. For everything outside Domino — NGINX, load balancers, and other
> services — Vault and srvguard close the distribution gap. Rotating the private
> key on every renewal cycle is the part most deployments have not solved yet.

---

## The Clock Is Already Ticking

For years, TLS certificate management was something you dealt with once a year.
Renew, deploy, forget about it for twelve months. That era is ending — not
gradually, but on a fixed, published schedule that is already in motion.

In April 2025, the CA/Browser Forum passed **Ballot SC-081v3**, with every
major browser (Apple, Google, Microsoft, Mozilla) voting yes and not a single
no vote among certificate issuers. The ballot introduces a phased reduction in
maximum TLS certificate validity:

```markdown
| Date                 | Maximum Validity     |
|:---------------------|:---------------------|
| ~~Until 2026-03-15~~ | ~~398 days~~         |
| **Now**              | **200 days**         |
| 2027-03-15           | 100 days             |
| **2029-03-15**       | **47 days**          |
```

The 47-day figure is not arbitrary — it corresponds to a 30-day renewal cycle
with a 17-day buffer. By 2029, if your infrastructure cannot automatically
renew and deploy certificates every month, it will break.

**March 15, 2026 has already passed.** The first deadline is not approaching —
it is already here. Certificates issued with more than 200-day validity are
no longer trusted by major browsers.

---

## This Has Been Building for a Long Time

The trajectory is not new. Let's Encrypt has issued 90-day certificates since
2015, explicitly to enforce automation. Apple unilaterally enforced a 398-day
maximum in September 2020 without even holding a CA/B Forum ballot — browsers
simply started rejecting longer certificates. Google published its intent to
move to 90-day certificates in 2023. SC-081 is the industry formalizing what
was already clearly the direction.

Let's Encrypt is moving even faster than SC-081 requires. They announced in
December 2025 that their default certificate lifetime will drop to **45 days**
by February 2028 — and they already offer very short-lived certificates (as
low as 6 days) today for environments that have fully automated renewal.

The message from every major browser and CA is the same: **manual certificate
management is over. Automation is no longer a best practice — it is a requirement.**

---

## Renewal Is Not Enough — Keys Must Rotate Too

This is where most discussions stop short. Shorter certificate lifetimes limit
how long a *certificate* is trusted — but they say nothing about the *private
key* underneath it.

Consider a typical pre-SC-081 deployment: a server running on the same private
key for three years, renewed annually with new certificates over that same key.
Each certificate had a one-year validity window, but the private key itself was
never rotated. That means three years of potential exposure — memory dumps,
insider access, side-channel attacks, or server compromise — all accumulating
on a single key that was never replaced.

Moving to 47-day certificate validity while keeping the same private key for
years defeats a significant part of the purpose. The certificate binding becomes
fresh every 47 days, but the underlying cryptographic material remains unchanged.

**Best practice: generate a new key pair on every renewal.** This bounds the
exposure of any single private key to one certificate cycle. Combined with
short validity periods, it means a compromised key has a hard expiry measured
in weeks, not years.

This is operationally more demanding. A new key means:

* A new CSR
* A new certificate issuance (not just a renewal)
* Distribution of a **new key and certificate** to every endpoint

At 47-day cycles, this happens roughly every six weeks — automatically and
reliably for every server in your infrastructure.

---

## What Domino CertMgr Already Does

HCL Domino's CertStore already handles key rollover correctly once it is
requested. When a key rollover is initiated via ACME, CertMgr executes the
full cycle cleanly:

1. Complete the ACME challenge (HTTP-01 or DNS-01) to prove domain control
2. Generate a new private key (RSA or ECDSA) and CSR
3. Submit the CSR to the ACME provider and receive the new certificate
4. Save the new TLS credentials document in CertStore
5. Archive the existing credentials document
6. Optionally revoke the previous certificate

The new key is only generated once the ACME authorization succeeds. There is
no point creating a key until you know the certificate can be issued.

The rollover mechanics are solid. What is not yet automated is the *triggering*
of a **new key** on each renewal cycle — today that requires explicit action.
The key rollover option is reset after a certificate is renewed.

Closing that gap — ensuring that every renewal automatically produces a new key
pair without manual intervention — is the next step. At 47-day cycles, that step
becomes mandatory. It would be possible to implement this using LotusScript.

### The Good News with CertMgr

Within Domino, TLS credentials are automatically distributed and well protected.
No additional automation is required beyond triggering key rotation.

Outside Domino — load balancers, reverse proxies, and other services —
a secure distribution mechanism is still required.

I am looking into the next steps and which additional
functionality could be added with a LotusScript agent. The agent could run in a
separate database and also push exportable TLS credentials to:

* HashiCorp Vault
* Kubernetes secrets
* Other targets in the future

---

## The Gap: Externally Deployed Certificates

The challenge is at the boundary. Domino servers often run alongside other
infrastructure — NGINX reverse proxies, load balancers, and other applications —
that require the same certificate. CertStore can manage the certificate lifecycle,
but securely distributing the resulting key and certificate to external systems
is a separate problem.

The naive solution — copying the key file to a shared location — has obvious
problems:

* Private keys on shared filesystems are difficult to protect
* Rotation requires coordinated restarts across multiple servers
* At 47-day intervals with key rotation, this becomes unsustainable manually
* Every copy of the key on disk increases the exposure surface

What is needed is a distribution layer that:

* Holds key material securely in memory, not in plain files
* Provides authenticated, audited access to each consuming server
* Triggers automatic reload when new TLS keys and certificates arrive
* Scales to frequent rotation without manual intervention

---

## HashiCorp Vault as a Distribution Layer

This is exactly the problem can HashiCorp Vault solve.

CertMgr (the Domino server task managing CertStore operations) pushes the
certificate chain, encrypted private key, and key password to Vault immediately
after issuance — entirely from memory, never writing the key to disk.

Each consuming server authenticates to Vault using AppRole credentials scoped
to its own secret path. A lightweight fetcher process on the host retrieves
the material from Vault, writes it to a tmpfs mount (memory-only), and signals
the application to reload. When the next renewal cycle runs, the same flow
repeats automatically.

The security properties align well with shorter lifetimes:

* Each renewal produces a new key and a new set of Vault credentials
* No key material ever sits in a plain file on any server
* Vault’s audit log provides a full record of every access
* A server compromise exposes only what was in memory at that moment

---

## The Timeline for Action

SC-081 is not optional. It is a CA/Browser Forum ballot passed unanimously by
every major browser. CAs that do not comply will lose their trusted status,
and certificates that exceed the limits will be rejected.

* 2026 → 200 days (already active)
* 2027 → 100 days
* 2029 → 47 days

This is not a future problem — it is already underway. The next step —
100-day certificates — takes effect March 15, 2027. That is the window to
build and validate the automation. By the time 47-day certificates arrive in
2029, the operational patterns need to be routine, not experimental.

---

## What I Am Building at Nash!Com

This is not a theoretical architecture. I am currently developing exactly
this solution — a HashiCorp Vault integration for HCL Domino CertMgr that
closes the external distribution gap.

CertMgr pushes the certificate chain, encrypted private key, and key password
to Vault immediately after issuance, entirely from memory. Each consuming
server — whether an NGINX reverse proxy, a load balancer, or another Domino
server — authenticates to Vault with scoped credentials and retrieves only
its own material. A lightweight host-side process writes the credentials to
a tmpfs mount and signals the application to reload. No key material ever
touches disk on the consuming server.

Combined with automated key rollover on each ACME renewal cycle, this covers
the full certificate distribution requirement: short-lived certificates,
fresh keys on every cycle, and secure distribution to every endpoint —
without manual intervention.

---

### Once the Vault Infrastructure Is in Place

Once Vault is running for certificate distribution, the same infrastructure
can address a second long-standing operational challenge: the Domino
**server.id password**.

Today, the server.id password either sits in `notes.ini` in plain text
(`ServerKeyFilePassword=`) or requires manual entry at every server restart.
Neither is acceptable in an automated environment.

With Vault already deployed, the solution is straightforward. A small
Extension Manager hook retrieves the password from Vault at startup — using
the same AppRole authentication pattern as the certificate clients — hands
it to Domino in memory, and clears the buffer immediately after use. The
password never touches disk, never appears in a config file, and the Domino
administrator gets full audit logging of every access via Vault.

Two problems, one infrastructure investment.

---

### Automating Commercial CAs

In parallel, I am looking at automating the full issuance flow with commercial CAs.
The good news: the market has already converged on ACME as the automation standard.
All major commercial CAs now support ACME with External Account Binding (EAB),
which ties an ACME client to an existing commercial CA account. Some also offer
a free tier: Let's Encrypt offers free certificates but only supports domain
validation certificates.

```markdown
| CA            | ACME + EAB            | Certificate Type         | Tested with Domino |
|:--------------|:----------------------|:-------------------------|:-------------------|
| Let's Encrypt | Yes (no EAB required) | Free                     | Yes                |
| SSL.com       | Yes                   | Both (Free + Commercial) | Yes                |
| ZeroSSL       | Yes                   | Both (Free + Commercial) | Yes                |
| Actalis       | Yes                   | Both (Free + Commercial) | Yes                |
| Sectigo       | Yes — DV, OV, EV      | Commercial               | Yes                |
| DigiCert      | Yes — DV, OV, EV      | Commercial               | No                 |
| GlobalSign    | Yes                   | Commercial               | No                 |
| GoDaddy       | Yes                   | Commercial               | No                 |
```

Commercial CAs typically require EAB credentials and an active account.
Testing commercial providers is often limited because:

* No free tier
* No public staging endpoints (unlike Let's Encrypt)

Only Sectigo could be fully tested in this setup because it provides a free
test account. Other commercial providers require paid accounts or enterprise
onboarding, which makes reproducible testing difficult.

If you work with one of those providers and you want to test it, let me know
and I would be happy to help. The community would benefit from additional
validation, and working configurations can be added to the GitHub project
listing the configuration.

CertMgr already supports EAB since Domino 12.0. This means the same automated
renewal flow that works with Let's Encrypt today can extend to any of these
commercial CAs without fundamental changes to the architecture — just different
ACME endpoints and EAB credentials. And with SC-081 making manual renewal
unworkable at 47-day cycles, this list will only grow as remaining holdouts
add ACME support to stay relevant.

---

## srvguard — The Last Mile

For services outside the Domino ecosystem — NGINX reverse proxies, load
balancers, and custom applications — I am working on `srvguard` as the
delivery mechanism.

`srvguard` is a small, statically compiled Go binary that runs as PID 1 in
a container with no shell, no bash, and no external dependencies. It:

1. Authenticates to Vault via AppRole
2. Fetches the secret for its own FQDN — the path is derived automatically
   from the container hostname, so no additional configuration is required
3. Writes credentials to a `tmpfs` mount — memory only, never touching disk
4. Processes configuration file templates using environment variable
   substitution, removing the need for tools like `envsubst`
5. Starts the managed service as a child process
6. Polls for secret version changes and signals the service to reload

For the Domino server itself, the private key password is delivered via the
**Linux kernel keyring**. The password is placed in the session keyring before
Domino loads, the Extension Manager hook reads it exactly once, revokes the
key immediately, and passes it to Domino in memory. No files, no environment
variables, and gone after first use.

---

## Open Source

All components described here are going to be published as open source under
the Apache 2.0 license:

* **[HashiCorp Vault Deployment project](https://github.com/nashcom/nsh-vault-deploy)** —
  HashiCorp Vault server configuration, Docker Compose stack, initialization
  scripts, policies, AppRole setup, and client examples including the C++
  push client used by CertMgr

* **[srvguard](https://github.com/nashcom/srvguard)** —
  The universal service guard binary for Linux (amd64 + arm64), C++ consumer
  library for native applications including the Domino Extension Manager
  hook pattern, NGINX example configuration, and GitHub Actions build pipeline

Commercial services around implementation, integration with specific
environments, and ongoing support are available through
**[Nash!Com](https://www.nashcom.de)**.

---

## References

* [CA/Browser Forum Ballot SC-081v3](https://cabforum.org/2025/04/11/ballot-sc081v3-introduce-schedule-of-reducing-validity-and-data-reuse-periods/) — the ballot text and vote results
* [CA/Browser Forum Ballot SC-063v4](https://cabforum.org/2023/07/14/ballot-sc063v4-make-ocsp-optional-require-crls-and-incentivize-automation/) — short-lived certificates and automation
* [Google: Moving Forward Together (2023)](https://googlechrome.github.io/chromerootprogram/moving-forward-together/) — Google's proposal
* [Apple: About upcoming limits on trusted certificates](https://support.apple.com/en-us/102028) — origin of the 398-day limit
* [Let's Encrypt: Why ninety-day lifetimes? (2015)](https://letsencrypt.org/2015/11/09/why-90-days) — automation rationale
* [Let's Encrypt: Moving to 45 days (December 2025)](https://letsencrypt.org/2025/12/02/from-90-to-45.html) — ahead of SC-081
* [DigiCert: TLS Certificate Lifetimes Will Officially Reduce to 47 Days](https://www.digicert.com/blog/tls-certificate-lifetimes-will-officially-reduce-to-47-days) — CA perspective

---

## Final Thought

This is not about certificates.

It is about **operational maturity under continuous rotation**.

By 2029, infrastructure that cannot automatically issue, rotate, distribute,
and reload TLS credentials will not function reliably.

The transition has already started.
