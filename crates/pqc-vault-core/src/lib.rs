//! # pqc-vault-core
//!
//! Hybrid post-quantum cryptography core for `pqc-vault`. This crate is a thin,
//! ergonomic layer over formally-verified and well-reviewed primitives:
//!
//! - **ML-KEM-768** via `libcrux-ml-kem` (formally verified, hax/F*)
//! - **ML-DSA-65** via `libcrux-ml-dsa` (formally verified)
//! - **X25519** via `x25519-dalek`
//! - **AES-256-GCM** via `aes-gcm`
//! - **HKDF-SHA256** via `hkdf` + `sha2`
//!
//! No cryptographic primitive is implemented here.

mod error;
mod format;
mod hybrid;
mod keys;
mod rng;
mod sign;

pub use error::{Error, Result};
pub use hybrid::{open, seal};
pub use keys::generate_keypair;
pub use sign::{generate_signing_keypair, sign, verify};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keypair_blob_sizes_match_spec() {
        let (pk, sk) = generate_keypair().unwrap();
        assert_eq!(pk.len(), keys::KEM_PUBLIC_BLOB);
        assert_eq!(sk.len(), keys::KEM_SECRET_BLOB);
        assert_eq!(&pk[0..4], b"PQCK");
        assert_eq!(pk[5], keys::KT_KEM_PUBLIC);
        assert_eq!(sk[5], keys::KT_KEM_SECRET);
    }

    #[test]
    fn seal_open_roundtrip() {
        let (pk, sk) = generate_keypair().unwrap();
        let msg = b"customer PII: dni=12345678Z iban=ES91...";
        let sealed = seal(msg, &pk).unwrap();
        let opened = open(&sealed, &sk).unwrap();
        assert_eq!(opened, msg);
    }

    #[test]
    fn roundtrip_empty_and_large() {
        let (pk, sk) = generate_keypair().unwrap();
        for size in [0usize, 1, 16, 1024, 100_000] {
            let msg = vec![0xABu8; size];
            let sealed = seal(&msg, &pk).unwrap();
            assert_eq!(open(&sealed, &sk).unwrap(), msg);
        }
    }

    #[test]
    fn sealed_has_expected_header() {
        let (pk, _sk) = generate_keypair().unwrap();
        let sealed = seal(b"x", &pk).unwrap();
        assert_eq!(&sealed[0..4], b"PQCV");
        assert_eq!(sealed[4], 1); // version
        assert_eq!(sealed[5], 1); // suite
        assert_eq!(sealed[6], 0); // flags
                                  // header + tag + 1 byte payload
        assert_eq!(sealed.len(), format::HEADER_LEN + format::TAG_LEN + 1);
    }

    #[test]
    fn wrong_key_fails_to_open() {
        let (pk, _sk) = generate_keypair().unwrap();
        let (_pk2, sk2) = generate_keypair().unwrap();
        let sealed = seal(b"secret", &pk).unwrap();
        assert_eq!(open(&sealed, &sk2), Err(Error::DecryptionFailed));
    }

    #[test]
    fn tampered_body_fails() {
        let (pk, sk) = generate_keypair().unwrap();
        let mut sealed = seal(b"secret message", &pk).unwrap();
        let last = sealed.len() - 1;
        sealed[last] ^= 0x01; // flip a tag bit
        assert_eq!(open(&sealed, &sk), Err(Error::DecryptionFailed));
    }

    #[test]
    fn tampered_header_fails() {
        let (pk, sk) = generate_keypair().unwrap();
        let mut sealed = seal(b"secret", &pk).unwrap();
        sealed[10] ^= 0x01; // flip a byte inside the ML-KEM ciphertext (AAD)
        assert_eq!(open(&sealed, &sk), Err(Error::DecryptionFailed));
    }

    #[test]
    fn bad_magic_is_invalid_ciphertext() {
        let (pk, sk) = generate_keypair().unwrap();
        let mut sealed = seal(b"secret", &pk).unwrap();
        sealed[0] ^= 0xFF;
        assert_eq!(open(&sealed, &sk), Err(Error::InvalidCiphertext));
    }

    #[test]
    fn truncated_is_invalid_ciphertext() {
        let (pk, sk) = generate_keypair().unwrap();
        let sealed = seal(b"secret", &pk).unwrap();
        assert_eq!(open(&sealed[..10], &sk), Err(Error::InvalidCiphertext));
    }

    #[test]
    fn public_key_rejected_as_secret() {
        let (pk, _sk) = generate_keypair().unwrap();
        let sealed = seal(b"secret", &pk).unwrap();
        // passing the public blob where a secret is expected must fail cleanly
        assert_eq!(open(&sealed, &pk), Err(Error::InvalidKey));
    }

    // ---- signatures (ML-DSA-65) ----

    #[test]
    fn signing_keypair_blob_sizes() {
        let (pk, sk) = generate_signing_keypair().unwrap();
        assert_eq!(pk.len(), sign::SIGN_PUBLIC_BLOB);
        assert_eq!(sk.len(), sign::SIGN_SECRET_BLOB);
        assert_eq!(&pk[0..4], b"PQCK");
        assert_eq!(pk[5], keys::KT_SIGN_PUBLIC);
        assert_eq!(sk[5], keys::KT_SIGN_SECRET);
    }

    #[test]
    fn sign_verify_roundtrip() {
        let (pk, sk) = generate_signing_keypair().unwrap();
        let msg = b"transfer 1000 EUR to IBAN ES91...";
        let sig = sign(msg, &sk).unwrap();
        assert_eq!(&sig[0..4], b"PQCS");
        assert_eq!(verify(msg, &sig, &pk), Ok(true));
    }

    #[test]
    fn verify_rejects_wrong_message() {
        let (pk, sk) = generate_signing_keypair().unwrap();
        let sig = sign(b"original", &sk).unwrap();
        assert_eq!(verify(b"tampered", &sig, &pk), Ok(false));
    }

    #[test]
    fn verify_rejects_wrong_key() {
        let (_pk, sk) = generate_signing_keypair().unwrap();
        let (pk2, _sk2) = generate_signing_keypair().unwrap();
        let sig = sign(b"msg", &sk).unwrap();
        assert_eq!(verify(b"msg", &sig, &pk2), Ok(false));
    }

    #[test]
    fn verify_rejects_tampered_signature() {
        let (pk, sk) = generate_signing_keypair().unwrap();
        let mut sig = sign(b"msg", &sk).unwrap();
        let last = sig.len() - 1;
        sig[last] ^= 0x01;
        assert_eq!(verify(b"msg", &sig, &pk), Ok(false));
    }

    #[test]
    fn verify_rejects_malformed_signature_blob() {
        let (pk, _sk) = generate_signing_keypair().unwrap();
        assert_eq!(verify(b"msg", b"not a signature", &pk), Ok(false));
    }

    #[test]
    fn verify_rejects_malformed_public_key() {
        let (_pk, sk) = generate_signing_keypair().unwrap();
        let sig = sign(b"msg", &sk).unwrap();
        // a KEM public key (wrong keytype) must not be accepted as a verify key
        let (kem_pk, _kem_sk) = generate_keypair().unwrap();
        assert_eq!(verify(b"msg", &sig, &kem_pk), Err(Error::InvalidKey));
    }

    #[test]
    fn signing_secret_rejected_as_kem_secret() {
        // cross-type misuse: a signing secret must not open a sealed message
        let (kem_pk, _kem_sk) = generate_keypair().unwrap();
        let (_spk, ssk) = generate_signing_keypair().unwrap();
        let sealed = seal(b"x", &kem_pk).unwrap();
        assert_eq!(open(&sealed, &ssk), Err(Error::InvalidKey));
    }
}
