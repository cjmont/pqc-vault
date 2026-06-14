//! Versioned, self-describing wire format for sealed messages.
//!
//! ```text
//! magic     4B  "PQCV"
//! version   1B  0x01
//! suite     1B  0x01 = X25519+ML-KEM768 / AES-256-GCM / HKDF-SHA256
//! flags     1B  0x00 (reserved for crypto-agility)
//! mlkem_ct  1088B
//! eph_pk    32B   ephemeral X25519 public key
//! nonce     12B   AES-GCM nonce
//! body      NB    AES-256-GCM ciphertext (N = total - HEADER_LEN - TAG)
//! tag       16B   GCM tag
//! ```
//!
//! The whole header (`magic..nonce`) is fed to AES-GCM as AAD, so any tamper of
//! version/suite/nonce makes `open` fail at the tag — no separate parse oracle.

use crate::error::{Error, Result};
use crate::keys::{MLKEM_CT, X25519_PK};

pub const MAGIC: [u8; 4] = *b"PQCV";
pub const VERSION: u8 = 1;
/// Suite 1: X25519 + ML-KEM-768 / AES-256-GCM / HKDF-SHA256.
pub const SUITE_HYBRID_V1: u8 = 1;

pub const NONCE_LEN: usize = 12;
pub const TAG_LEN: usize = 16;

// Field offsets within the header.
const OFF_MAGIC: usize = 0;
const OFF_VERSION: usize = 4;
const OFF_SUITE: usize = 5;
const OFF_FLAGS: usize = 6;
const OFF_MLKEM_CT: usize = 7;
const OFF_EPH_PK: usize = OFF_MLKEM_CT + MLKEM_CT;
const OFF_NONCE: usize = OFF_EPH_PK + X25519_PK;

/// Total length of the fixed header (everything used as AAD).
pub const HEADER_LEN: usize = OFF_NONCE + NONCE_LEN;

/// Borrowed view of a parsed sealed message.
pub struct Parsed<'a> {
    /// The full header bytes (used as AEAD AAD).
    pub header: &'a [u8],
    pub mlkem_ct: &'a [u8],
    pub eph_pk: &'a [u8],
    pub nonce: &'a [u8],
    /// AEAD ciphertext including the trailing GCM tag.
    pub body_and_tag: &'a [u8],
}

/// Build the fixed header bytes. The returned vector is exactly `HEADER_LEN`
/// long and is used both as the AES-GCM AAD and as the output prefix.
pub fn header(mlkem_ct: &[u8], eph_pk: &[u8], nonce: &[u8]) -> Vec<u8> {
    debug_assert_eq!(mlkem_ct.len(), MLKEM_CT);
    debug_assert_eq!(eph_pk.len(), X25519_PK);
    debug_assert_eq!(nonce.len(), NONCE_LEN);
    let mut out = Vec::with_capacity(HEADER_LEN);
    out.extend_from_slice(&MAGIC);
    out.push(VERSION);
    out.push(SUITE_HYBRID_V1);
    out.push(0); // flags
    out.extend_from_slice(mlkem_ct);
    out.extend_from_slice(eph_pk);
    out.extend_from_slice(nonce);
    out
}

/// Parse and structurally validate a sealed message. Does no cryptography.
pub fn parse(buf: &[u8]) -> Result<Parsed<'_>> {
    if buf.len() < HEADER_LEN + TAG_LEN {
        return Err(Error::InvalidCiphertext);
    }
    if buf[OFF_MAGIC..OFF_MAGIC + 4] != MAGIC
        || buf[OFF_VERSION] != VERSION
        || buf[OFF_SUITE] != SUITE_HYBRID_V1
        || buf[OFF_FLAGS] != 0
    {
        return Err(Error::InvalidCiphertext);
    }
    Ok(Parsed {
        header: &buf[..HEADER_LEN],
        mlkem_ct: &buf[OFF_MLKEM_CT..OFF_MLKEM_CT + MLKEM_CT],
        eph_pk: &buf[OFF_EPH_PK..OFF_EPH_PK + X25519_PK],
        nonce: &buf[OFF_NONCE..OFF_NONCE + NONCE_LEN],
        body_and_tag: &buf[HEADER_LEN..],
    })
}
