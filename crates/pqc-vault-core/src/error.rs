//! Opaque error type.
//!
//! Errors never carry secret material and never distinguish *why* a decryption
//! failed (bad tag vs. bad KEM vs. wrong key) — every post-parse failure during
//! `open` collapses to a single `DecryptionFailed` to avoid giving an attacker
//! a decryption / padding oracle. Structural parse errors (wrong magic, wrong
//! length) are reported separately because they reveal nothing secret.

use core::fmt;

/// Result alias for pqc-vault-core operations.
pub type Result<T> = core::result::Result<T, Error>;

/// The single error type exposed by this crate. `Display` output is generic.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// A key blob was malformed (bad magic/version/type/length).
    InvalidKey,
    /// A sealed message was structurally malformed (bad magic/version/length).
    InvalidCiphertext,
    /// Decryption failed. Intentionally uniform: covers AEAD tag failure,
    /// wrong recipient key, and any other cryptographic failure during `open`.
    DecryptionFailed,
    /// A signature failed to verify or was malformed.
    VerificationFailed,
    /// The system RNG could not be read.
    RandomnessUnavailable,
    /// An unexpected internal failure (should not occur with valid inputs).
    Internal,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let msg = match self {
            Error::InvalidKey => "invalid key",
            Error::InvalidCiphertext => "invalid ciphertext format",
            Error::DecryptionFailed => "decryption failed",
            Error::VerificationFailed => "verification failed",
            Error::RandomnessUnavailable => "system randomness unavailable",
            Error::Internal => "internal error",
        };
        f.write_str(msg)
    }
}

impl std::error::Error for Error {}
