# pqc-vault

> Hybrid post-quantum encryption and signatures for Node.js — a libsodium-style
> API over a formally-verified backend. Built for fintech that needs to protect
> data **today** against **harvest-now, decrypt-later**.

[![CI](https://github.com/cjmont/pqc-vault/actions/workflows/ci.yml/badge.svg)](https://github.com/cjmont/pqc-vault/actions/workflows/ci.yml)
**ML-KEM-768 + ML-DSA-65** · hybrid with X25519 / AES-256-GCM · 130/130 NIST ACVP test vectors

`pqc-vault` provides **hybrid** (classical + post-quantum) encryption and
signatures using **ML-KEM-768** and **ML-DSA-65**, via the formally-verified
[libcrux](https://github.com/cryspen/libcrux) backend. It does **not** implement
any cryptographic primitive by hand — it is an ergonomics-and-trust layer over
reviewed code.

## Why hybrid?

`pqc-vault` combines classical and post-quantum cryptography:

- **X25519** — battle-tested classical key agreement; protects you if the new
  lattice schemes are ever weakened.
- **ML-KEM-768** — post-quantum KEM; protects you against a future quantum
  computer decrypting traffic captured today.

An attacker must break **both** to recover your data.

## Install

```bash
npm install pqc-vault
```

Prebuilt native binaries ship for `linux-x64-gnu`, `linux-arm64-gnu`,
`darwin-arm64` (Apple Silicon), and `win32-x64`. **`npm install` never compiles
Rust on your machine.** ESM and CommonJS are both supported (Node 18+).

## Quickstart (10 lines)

```js
import { generateKeypair, seal, open } from "pqc-vault";

const { publicKey, secretKey } = await generateKeypair();

const pii = Buffer.from(JSON.stringify({ iban: "ES91...", dni: "12345678Z" }));

const sealed = await seal(pii, publicKey); // store/transmit this safely
const recovered = await open(sealed, secretKey); // only the secret key opens it

console.log(JSON.parse(recovered.toString())); // { iban: "ES91...", dni: ... }
```

All functions accept `Uint8Array` or Node `Buffer` and return a `Buffer`. Full
TypeScript types are included.

## Harvest-now, decrypt-later

Adversaries record encrypted traffic **now** to decrypt it once quantum
computers mature. Data with a long confidentiality lifetime — PII, financial
records, KYC documents — is the prime target. Sealing it with `pqc-vault` today
means a recorded ciphertext stays protected by ML-KEM-768 even after RSA/ECDH
fall.

See [`examples/protect-pii.mjs`](examples/protect-pii.mjs) for a runnable
end-to-end example (`node examples/protect-pii.mjs`).

## API

```ts
// Encryption (hybrid public-key, libsodium-style sealed boxes)
generateKeypair(): Promise<{ publicKey: Buffer; secretKey: Buffer }>;
seal(data: Uint8Array, recipientPublicKey: Uint8Array): Promise<Buffer>;
open(ciphertext: Uint8Array, recipientSecretKey: Uint8Array): Promise<Buffer>;

// Signatures (ML-DSA-65)
generateSigningKeypair(): Promise<{ publicKey: Buffer; secretKey: Buffer }>;
sign(message: Uint8Array, secretKey: Uint8Array): Promise<Buffer>;
verify(message: Uint8Array, signature: Uint8Array, publicKey: Uint8Array): Promise<boolean>;
```

## How `seal` / `open` work (the hybrid scheme)

```
seal(data, recipientPublicKey):
  1. ephemeral X25519  →  ss_classical = DH(ephemeral_sk, recipient_x25519_pk)
  2. ML-KEM-768 encaps →  (kem_ct, ss_pq) = Encaps(recipient_mlkem_pk)
  3. key = HKDF-SHA256(ikm = ss_pq ‖ ss_classical,
                       salt = "pqc-vault/v1/salt",
                       info = "pqc-vault/v1/seal" ‖ suite ‖ kem_ct ‖ ephemeral_pk)
  4. body‖tag = AES-256-GCM(key, nonce, plaintext, aad = header)
```

The output is a versioned, self-describing binary message:

```
magic "PQCV" (4) | version (1) | suite (1) | flags (1)
                 | ML-KEM ciphertext (1088) | ephemeral X25519 pk (32)
                 | AES-GCM nonce (12) | body (N) | GCM tag (16)
```

- The **entire header is bound as AES-GCM AAD**, so tampering with the version,
  suite, KEM ciphertext, ephemeral key, or nonce makes `open` fail at the tag.
- The HKDF `info` binds the transcript (suite + KEM ciphertext + ephemeral key),
  giving domain separation and resistance to cross-protocol reuse.
- The `version` / `suite` / `flags` bytes provide **crypto-agility** for future
  algorithm changes without breaking old ciphertexts.

Both shared secrets feed the KDF, so breaking only X25519 **or** only ML-KEM is
insufficient to recover the AES key.

## Trust signals

- **ACVP conformance.** The pinned libcrux backend is validated byte-for-byte
  against the official NIST [ACVP test vectors](https://github.com/usnistgov/ACVP-Server)
  for ML-KEM-768 and ML-DSA-65 (key generation, encaps/decaps, sig gen/ver) in
  CI — **130/130 passing**. Vendored vectors are pinned by SHA-256.
- **Formally-verified primitives.** ML-KEM and ML-DSA come from libcrux, which
  is verified with hax/F\*.
- **Signed releases.** Published with **npm provenance** (SLSA attestation via
  OIDC; verify with `npm audit signatures`) and prebuilt binaries signed with
  **cosign** (keyless).
- **No secret/oracle leakage.** `open` returns a single generic error for every
  cryptographic failure (bad key, tampered ciphertext, tampered tag) and never
  distinguishes the cause.
- **System entropy.** All randomness comes from the OS CSPRNG via `getrandom`
  (`getrandom(2)` / `BCryptGenRandom` / `getentropy`); no userspace PRNG is
  seeded.

## Related

- [`pqc-vault-tfm`](https://www.npmjs.com/package/pqc-vault-tfm) — the author's
  academic reference implementation (from-scratch, educational). `pqc-vault` is
  the production package that delegates to verified backends instead.

## License

[Apache-2.0](LICENSE)
