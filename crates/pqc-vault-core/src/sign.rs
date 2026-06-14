//! Digital signatures with ML-DSA-65, pure variant.
//!
//! Signing keys are serialized as self-describing `PQCK` blobs (same scheme as
//! the KEM keys, with signing key-types). Signatures are wrapped in a small
//! versioned `PQCS` header for crypto-agility:
//!
//! ```text
//! "PQCS" (4) | version (1) | suite (1) | raw ML-DSA-65 signature
//! ```
//!
//! A fixed context string provides domain separation.

use libcrux_ml_dsa::ml_dsa_65::{
    self, MLDSA65Signature, MLDSA65SigningKey, MLDSA65VerificationKey,
};
use zeroize::Zeroize;

use crate::error::{Error, Result};
use crate::keys::{self, HDR, KT_SIGN_PUBLIC, KT_SIGN_SECRET};
use crate::rng;

/// ML-DSA-65 verification (public) key length.
pub const SIGN_PK: usize = MLDSA65VerificationKey::len();
/// ML-DSA-65 signing (secret) key length.
pub const SIGN_SK: usize = MLDSA65SigningKey::len();
/// ML-DSA-65 raw signature length.
pub const SIGN_RAW: usize = MLDSA65Signature::len();

/// Serialized signing public-key blob length.
pub const SIGN_PUBLIC_BLOB: usize = HDR + SIGN_PK;
/// Serialized signing secret-key blob length.
pub const SIGN_SECRET_BLOB: usize = HDR + SIGN_SK;

// Signature wire header.
const SIG_MAGIC: [u8; 4] = *b"PQCS";
const SIG_VERSION: u8 = 1;
const SIG_SUITE_MLDSA65: u8 = 1;
const SIG_HDR: usize = 4 + 1 + 1;
/// Total length of a serialized signature blob.
pub const SIGNATURE_BLOB: usize = SIG_HDR + SIGN_RAW;

/// Domain-separation context string for signing.
const SIGN_CONTEXT: &[u8] = b"pqc-vault/v1/sign";

/// Generate an ML-DSA-65 signing keypair. Returns `(public_blob, secret_blob)`.
pub fn generate_signing_keypair() -> Result<(Vec<u8>, Vec<u8>)> {
    let seed = rng::array::<{ libcrux_ml_dsa::KEY_GENERATION_RANDOMNESS_SIZE }>()?;
    let kp = ml_dsa_65::generate_key_pair(seed);

    let mut public = Vec::with_capacity(SIGN_PUBLIC_BLOB);
    keys::write_header(&mut public, KT_SIGN_PUBLIC);
    public.extend_from_slice(kp.verification_key.as_ref());

    let mut secret = Vec::with_capacity(SIGN_SECRET_BLOB);
    keys::write_header(&mut secret, KT_SIGN_SECRET);
    secret.extend_from_slice(kp.signing_key.as_ref());

    Ok((public, secret))
}

/// Sign `message` with a signing secret-key blob. Returns a signature blob.
pub fn sign(message: &[u8], secret_blob: &[u8]) -> Result<Vec<u8>> {
    keys::check_header(secret_blob, KT_SIGN_SECRET, SIGN_SECRET_BLOB)?;
    let mut sk_bytes = [0u8; SIGN_SK];
    sk_bytes.copy_from_slice(&secret_blob[HDR..]);
    let signing_key = MLDSA65SigningKey::new(sk_bytes);

    let randomness = rng::array::<{ libcrux_ml_dsa::SIGNING_RANDOMNESS_SIZE }>()?;
    let signature = ml_dsa_65::sign(&signing_key, message, SIGN_CONTEXT, randomness)
        .map_err(|_| Error::Internal)?;

    sk_bytes.zeroize();

    let mut out = Vec::with_capacity(SIGNATURE_BLOB);
    out.extend_from_slice(&SIG_MAGIC);
    out.push(SIG_VERSION);
    out.push(SIG_SUITE_MLDSA65);
    out.extend_from_slice(signature.as_ref());
    Ok(out)
}

/// Verify `signature_blob` over `message` against a signing public-key blob.
///
/// Returns `Ok(true)` / `Ok(false)` for a well-formed signature that is valid /
/// invalid. A malformed signature blob is treated as untrusted input and yields
/// `Ok(false)`. A malformed public-key blob is a caller error: `Err(InvalidKey)`.
pub fn verify(message: &[u8], signature_blob: &[u8], public_blob: &[u8]) -> Result<bool> {
    keys::check_header(public_blob, KT_SIGN_PUBLIC, SIGN_PUBLIC_BLOB)?;
    let mut pk_bytes = [0u8; SIGN_PK];
    pk_bytes.copy_from_slice(&public_blob[HDR..]);
    let verification_key = MLDSA65VerificationKey::new(pk_bytes);

    // Untrusted signature: any structural problem means "not valid".
    if signature_blob.len() != SIGNATURE_BLOB
        || signature_blob[0..4] != SIG_MAGIC
        || signature_blob[4] != SIG_VERSION
        || signature_blob[5] != SIG_SUITE_MLDSA65
    {
        return Ok(false);
    }
    let mut sig_bytes = [0u8; SIGN_RAW];
    sig_bytes.copy_from_slice(&signature_blob[SIG_HDR..]);
    let signature = MLDSA65Signature::new(sig_bytes);

    Ok(ml_dsa_65::verify(&verification_key, message, SIGN_CONTEXT, &signature).is_ok())
}
