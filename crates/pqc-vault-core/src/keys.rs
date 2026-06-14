//! Hybrid key material: X25519 (classical) + ML-KEM-768 (post-quantum).
//!
//! A recipient holds a *static* hybrid keypair. Public and secret keys are
//! serialized as self-describing blobs so that passing the wrong key (public
//! where secret is expected, or a signing key to `seal`) fails cleanly instead
//! of producing garbage.
//!
//! Blob layout:
//! ```text
//! "PQCK" (4) | version (1) | keytype (1) | material...
//! ```

use libcrux_ml_kem::mlkem768;
use x25519_dalek::{PublicKey as XPublicKey, StaticSecret as XSecret};
use zeroize::Zeroize;

use crate::error::{Error, Result};
use crate::rng;

/// Magic prefix for all key blobs.
pub const KEY_MAGIC: [u8; 4] = *b"PQCK";
/// Key blob format version.
pub const KEY_VERSION: u8 = 1;

// Key-type discriminants.
pub const KT_KEM_PUBLIC: u8 = 0x01;
pub const KT_KEM_SECRET: u8 = 0x02;
#[allow(dead_code)] // used in phase 3 (signatures)
pub const KT_SIGN_PUBLIC: u8 = 0x03;
#[allow(dead_code)] // used in phase 3 (signatures)
pub const KT_SIGN_SECRET: u8 = 0x04;

// Component sizes.
pub const X25519_PK: usize = 32;
pub const X25519_SK: usize = 32;
pub const MLKEM_PK: usize = 1184;
pub const MLKEM_SK: usize = 2400;
pub const MLKEM_CT: usize = 1088;
pub const SHARED_SECRET: usize = 32;

/// Blob header length: magic + version + keytype.
pub(crate) const HDR: usize = 4 + 1 + 1;

/// Serialized KEM public-key blob length.
pub const KEM_PUBLIC_BLOB: usize = HDR + X25519_PK + MLKEM_PK;
/// Serialized KEM secret-key blob length.
pub const KEM_SECRET_BLOB: usize = HDR + X25519_SK + MLKEM_SK;

/// A recipient's decoded public key (borrowed views into a validated blob).
pub struct KemPublicKey {
    pub x25519: [u8; X25519_PK],
    pub mlkem: [u8; MLKEM_PK],
}

/// A recipient's decoded secret key. Zeroized on drop.
pub struct KemSecretKey {
    pub x25519: [u8; X25519_SK],
    pub mlkem: [u8; MLKEM_SK],
}

impl Drop for KemSecretKey {
    fn drop(&mut self) {
        self.x25519.zeroize();
        self.mlkem.zeroize();
    }
}

pub(crate) fn write_header(out: &mut Vec<u8>, keytype: u8) {
    out.extend_from_slice(&KEY_MAGIC);
    out.push(KEY_VERSION);
    out.push(keytype);
}

pub(crate) fn check_header(blob: &[u8], keytype: u8, total: usize) -> Result<()> {
    if blob.len() != total
        || blob[0..4] != KEY_MAGIC
        || blob[4] != KEY_VERSION
        || blob[5] != keytype
    {
        return Err(Error::InvalidKey);
    }
    Ok(())
}

/// Generate a fresh hybrid KEM keypair. Returns `(public_blob, secret_blob)`.
pub fn generate_keypair() -> Result<(Vec<u8>, Vec<u8>)> {
    // X25519 static keypair from system randomness.
    let x_sk_bytes = rng::array::<X25519_SK>()?;
    let x_secret = XSecret::from(x_sk_bytes);
    let x_public = XPublicKey::from(&x_secret);

    // ML-KEM-768 keypair from a 64-byte system seed.
    let kem_seed = rng::array::<{ libcrux_ml_kem::KEY_GENERATION_SEED_SIZE }>()?;
    let kem_kp = mlkem768::generate_key_pair(kem_seed);

    let mut public = Vec::with_capacity(KEM_PUBLIC_BLOB);
    write_header(&mut public, KT_KEM_PUBLIC);
    public.extend_from_slice(x_public.as_bytes());
    public.extend_from_slice(kem_kp.pk());

    let mut secret = Vec::with_capacity(KEM_SECRET_BLOB);
    write_header(&mut secret, KT_KEM_SECRET);
    secret.extend_from_slice(x_secret.as_bytes());
    secret.extend_from_slice(kem_kp.sk());

    Ok((public, secret))
}

/// Decode and validate a KEM public-key blob.
pub fn decode_public(blob: &[u8]) -> Result<KemPublicKey> {
    check_header(blob, KT_KEM_PUBLIC, KEM_PUBLIC_BLOB)?;
    let mut x25519 = [0u8; X25519_PK];
    let mut mlkem = [0u8; MLKEM_PK];
    x25519.copy_from_slice(&blob[HDR..HDR + X25519_PK]);
    mlkem.copy_from_slice(&blob[HDR + X25519_PK..]);
    Ok(KemPublicKey { x25519, mlkem })
}

/// Decode and validate a KEM secret-key blob.
pub fn decode_secret(blob: &[u8]) -> Result<KemSecretKey> {
    check_header(blob, KT_KEM_SECRET, KEM_SECRET_BLOB)?;
    let mut x25519 = [0u8; X25519_SK];
    let mut mlkem = [0u8; MLKEM_SK];
    x25519.copy_from_slice(&blob[HDR..HDR + X25519_SK]);
    mlkem.copy_from_slice(&blob[HDR + X25519_SK..]);
    Ok(KemSecretKey { x25519, mlkem })
}
