# Security Policy

## Supported versions

`pqc-vault` is pre-1.0. Security fixes are applied to the latest published
`0.x` release. Pin a version and watch releases.

| Version | Supported |
| ------- | --------- |
| 0.1.x   | ✅        |

## Reporting a vulnerability

**Please do not open a public GitHub issue for security vulnerabilities.**

Report privately via GitHub's [private vulnerability reporting](https://docs.github.com/en/code-security/security-advisories/guidance-on-reporting-and-writing-information-about-vulnerabilities/privately-reporting-a-security-vulnerability)
("Report a vulnerability" under the repository's **Security** tab), or by email
to the maintainer (**carlosmontanor** on npm).

Please include:

- A description of the issue and its impact.
- Steps to reproduce or a proof of concept.
- Affected version(s) and platform.

### What to expect

- **Acknowledgement** within 72 hours.
- An initial assessment within 7 days.
- Coordinated disclosure: we will agree on a disclosure timeline with you and
  credit you (if you wish) once a fix is released.

## Scope

`pqc-vault` is a packaging and ergonomics layer. Cryptographic primitives are
provided by third-party crates (`libcrux-ml-kem`, `libcrux-ml-dsa`,
`x25519-dalek`, `aes-gcm`, `hkdf`). Vulnerabilities in those upstreams should
also be reported to their respective maintainers; we will track and bump
affected dependencies.

In scope:

- The hybrid construction, key/message wire formats, and KDF usage in this repo.
- The Node binding and TypeScript API (input handling, error leakage).
- The build/release pipeline (supply-chain integrity).
