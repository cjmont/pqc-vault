//! System randomness.
//!
//! All randomness in pqc-vault comes from the operating system CSPRNG via the
//! `getrandom` crate, which reads from the platform's secure source:
//! `getrandom(2)` / `/dev/urandom` on Linux, `getentropy(2)` on macOS, and
//! `BCryptGenRandom` / `ProcessPrng` on Windows. No userspace PRNG is seeded
//! or reused.

use crate::error::{Error, Result};

/// Fill `buf` with cryptographically secure random bytes from the OS CSPRNG.
pub fn fill(buf: &mut [u8]) -> Result<()> {
    getrandom::fill(buf).map_err(|_| Error::RandomnessUnavailable)
}

/// Return a fixed-size array of secure random bytes.
pub fn array<const N: usize>() -> Result<[u8; N]> {
    let mut out = [0u8; N];
    fill(&mut out)?;
    Ok(out)
}
