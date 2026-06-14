# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] - 2026-06-14

### Added

- Hybrid public-key encryption (`generateKeypair`, `seal`, `open`) combining
  **X25519** and **ML-KEM-768** via HKDF-SHA256 into an AES-256-GCM sealed box,
  with a versioned, self-describing `PQCV` wire format and the full header bound
  as AEAD AAD.
- Post-quantum signatures (`generateSigningKeypair`, `sign`, `verify`) using
  **ML-DSA-65** (pure variant) with a fixed domain-separation context and a
  versioned `PQCS` signature format.
- Rust core (`pqc-vault-core`) over the formally-verified libcrux backend plus
  RustCrypto for X25519 / AES-GCM / HKDF; primitives are never hand-rolled.
- Node.js binding via napi-rs; every operation runs on the libuv thread pool and
  returns a real `Promise`. Inputs accept `Uint8Array` or `Buffer`.
- Dual ESM + CommonJS distribution with generated TypeScript declarations.
- **ACVP conformance** against the official NIST vectors for ML-KEM-768 and
  ML-DSA-65 (130/130 passing), with vendored vectors pinned by SHA-256.
- Property tests: roundtrip, wrong-key rejection, ciphertext/tag tamper
  detection, and cross-type key-misuse rejection.
- CI (Rust fmt/clippy/tests + Node matrix on Linux/macOS/Windows × Node 20/22).
- Release pipeline with multi-platform prebuilds, **npm provenance** (SLSA), and
  **cosign** keyless signing of prebuilt binaries.

[Unreleased]: https://github.com/cjmont/pqc-vault/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/cjmont/pqc-vault/releases/tag/v0.1.0
