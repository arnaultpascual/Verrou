# Security Policy

Verrou is an offline-first, encrypted vault — security *is* the product. We take
reports seriously and aim to respond quickly.

> **Status:** Verrou is in **pre-1.0 alpha** and has **not** yet undergone an
> external security audit (one is planned before 1.0). Treat it as experimental:
> do not rely on it as the *only* copy of irreplaceable secrets.

## Supported versions

Before 1.0, only the **latest released version** receives security fixes. There
are no security backports to older pre-releases.

| Version        | Supported          |
| -------------- | ------------------ |
| latest `0.x`   | :white_check_mark: |
| older `0.x`    | :x:                |

## Reporting a vulnerability

**Please do not report security vulnerabilities through public GitHub issues,
discussions, or pull requests.**

Use GitHub's **private vulnerability reporting**:

1. Go to the repository's **[Security advisories — report a vulnerability](https://github.com/arnaultpascual/Verrou/security/advisories/new)** page.
2. Provide as much detail as you can (see below).

This keeps the report private until a fix is coordinated. A dedicated security
email and PGP key may be published here later; until then, the private advisory
flow is the canonical channel.

### What to include

- Affected version or commit SHA, and operating system.
- A clear description of the issue and its security impact.
- Reproduction steps and, if possible, a minimal proof of concept.
- Any suggested remediation.

**Never include real secrets** — passwords, seed phrases, recovery codes, TOTP
secrets, vault files (`vault.db`), or exports (`*.verrou`). Use throwaway test
data.

## What to expect

We practice **coordinated disclosure**. As a volunteer-maintained pre-1.0
project these are best-effort targets, not guarantees:

| Stage                | Target            |
| -------------------- | ----------------- |
| Acknowledgement      | within 72 hours   |
| Initial triage       | within 7 days     |
| Fix / mitigation     | severity-dependent |

We will keep you updated, agree on a disclosure timeline, and credit you in the
advisory and changelog unless you prefer to remain anonymous.

## Scope

The cryptographic design and threat model — assets, adversaries, trust
assumptions, and **explicit non-goals** — are documented in
[`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) and
[`docs/CRYPTO_DESIGN.md`](docs/CRYPTO_DESIGN.md). Please read them before
reporting.

**In scope**

- `verrou-crypto-core`, `verrou-vault`, and the `src-tauri` IPC boundary.
- Cryptographic weaknesses, key-handling/memory-exposure bugs, and
  authentication-bypass on sensitive operations.
- Import/export parsing (untrusted input) and the export envelope.
- Build and release integrity.

**Out of scope** (documented non-goals — see the threat model)

- A compromised operating system, kernel, or root-level malware; hardware
  keyloggers/implants.
- An attacker with access to an **already-unlocked** vault session.
- Extraction of the biometric secret from a compromised OS keychain
  (non-extractable hardware binding is roadmapped).
- Coercion to unlock ("rubber-hose"); there is no duress mechanism.
- Denial of service against the local app process itself.

Reports against documented out-of-scope items may be closed as such, but we
still appreciate a heads-up if you believe the model itself is wrong.

## Safe harbor

We consider good-faith security research conducted in line with this policy to
be authorized. We will not pursue legal action against researchers who:

- Make a good-faith effort to avoid privacy violations and data destruction.
- Only test against their **own** vault / test data.
- Do not exfiltrate data beyond the minimum needed to demonstrate the issue.
- Give us a reasonable chance to remediate before public disclosure.
