//! Hybrid public-key encryption: `seal` / `open`.
//!
//! Scheme (suite 1):
//!   1. Ephemeral X25519 DH against the recipient's static X25519 key.
//!   2. ML-KEM-768 encapsulation against the recipient's static ML-KEM key.
//!   3. `key = HKDF-SHA256(ikm = mlkem_ss || x25519_ss, salt, info)`, where
//!      `info` binds the protocol label, suite, ML-KEM ciphertext and ephemeral
//!      X25519 public key (transcript binding).
//!   4. `AES-256-GCM` over the payload, with the full wire header as AAD.
//!
//! Both shared secrets must be combined for an attacker to recover the key:
//! breaking only X25519 (classical) or only ML-KEM (quantum) is insufficient.

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use hkdf::Hkdf;
use libcrux_ml_kem::mlkem768::{self, MlKem768Ciphertext, MlKem768PrivateKey, MlKem768PublicKey};
use sha2::Sha256;
use x25519_dalek::{PublicKey as XPublicKey, StaticSecret as XSecret};
use zeroize::Zeroize;

use crate::error::{Error, Result};
use crate::format::{self, NONCE_LEN};
use crate::keys::{self, SHARED_SECRET, X25519_PK};
use crate::rng;

/// HKDF salt: fixed protocol label (domain separation across versions).
const HKDF_SALT: &[u8] = b"pqc-vault/v1/salt";
/// HKDF info prefix.
const HKDF_INFO: &[u8] = b"pqc-vault/v1/seal";

/// Derive the 32-byte AES-256 key from the two shared secrets, binding the
/// transcript (suite, ML-KEM ciphertext, ephemeral X25519 key) into `info`.
fn derive_key(
    mlkem_ss: &[u8; SHARED_SECRET],
    x25519_ss: &[u8; SHARED_SECRET],
    mlkem_ct: &[u8],
    eph_pk: &[u8],
) -> [u8; 32] {
    let mut ikm = [0u8; SHARED_SECRET * 2];
    ikm[..SHARED_SECRET].copy_from_slice(mlkem_ss);
    ikm[SHARED_SECRET..].copy_from_slice(x25519_ss);

    let mut info = Vec::with_capacity(HKDF_INFO.len() + 1 + mlkem_ct.len() + eph_pk.len());
    info.extend_from_slice(HKDF_INFO);
    info.push(format::SUITE_HYBRID_V1);
    info.extend_from_slice(mlkem_ct);
    info.extend_from_slice(eph_pk);

    let hk = Hkdf::<Sha256>::new(Some(HKDF_SALT), &ikm);
    let mut key = [0u8; 32];
    // expand only fails on absurd output lengths; 32 is always valid.
    hk.expand(&info, &mut key).expect("HKDF expand of 32 bytes");

    ikm.zeroize();
    key
}

/// Encrypt `data` to a recipient identified by their KEM public-key blob.
pub fn seal(data: &[u8], recipient_public: &[u8]) -> Result<Vec<u8>> {
    let recipient = keys::decode_public(recipient_public)?;

    // 1. Ephemeral X25519.
    let eph_sk_bytes = rng::array::<X25519_PK>()?;
    let eph_secret = XSecret::from(eph_sk_bytes);
    let eph_public = XPublicKey::from(&eph_secret);
    let x25519_ss = eph_secret.diffie_hellman(&XPublicKey::from(recipient.x25519));

    // 2. ML-KEM-768 encapsulation.
    let kem_pk = MlKem768PublicKey::from(recipient.mlkem);
    let enc_rand = rng::array::<SHARED_SECRET>()?;
    let (kem_ct, mlkem_ss) = mlkem768::encapsulate(&kem_pk, enc_rand);

    // 3. Derive AES key.
    let eph_pk_bytes = *eph_public.as_bytes();
    let mut key = derive_key(
        &mlkem_ss,
        x25519_ss.as_bytes(),
        kem_ct.as_ref(),
        &eph_pk_bytes,
    );

    // 4. AES-256-GCM, header as AAD.
    let nonce_bytes = rng::array::<NONCE_LEN>()?;
    let header = format::header(kem_ct.as_ref(), &eph_pk_bytes, &nonce_bytes);

    let cipher = Aes256Gcm::new_from_slice(&key).expect("32-byte key");
    let body_and_tag = cipher
        .encrypt(
            Nonce::from_slice(&nonce_bytes),
            Payload {
                msg: data,
                aad: &header,
            },
        )
        .map_err(|_| Error::DecryptionFailed)?;
    key.zeroize();

    let mut out = header;
    out.extend_from_slice(&body_and_tag);
    Ok(out)
}

/// Decrypt a sealed message using the recipient's KEM secret-key blob.
pub fn open(sealed: &[u8], recipient_secret: &[u8]) -> Result<Vec<u8>> {
    let parsed = format::parse(sealed)?;
    let recipient = keys::decode_secret(recipient_secret)?;

    // X25519: DH of recipient static secret with the ephemeral public key.
    let mut eph_pk = [0u8; X25519_PK];
    eph_pk.copy_from_slice(parsed.eph_pk);
    let x_secret = XSecret::from(recipient.x25519);
    let x25519_ss = x_secret.diffie_hellman(&XPublicKey::from(eph_pk));

    // ML-KEM: decapsulate to recover the shared secret.
    let kem_sk = MlKem768PrivateKey::from(recipient.mlkem);
    let kem_ct =
        MlKem768Ciphertext::try_from(parsed.mlkem_ct).map_err(|_| Error::DecryptionFailed)?;
    let mlkem_ss = mlkem768::decapsulate(&kem_sk, &kem_ct);

    let mut key = derive_key(
        &mlkem_ss,
        x25519_ss.as_bytes(),
        parsed.mlkem_ct,
        parsed.eph_pk,
    );

    let cipher = Aes256Gcm::new_from_slice(&key).expect("32-byte key");
    let plaintext = cipher
        .decrypt(
            Nonce::from_slice(parsed.nonce),
            Payload {
                msg: parsed.body_and_tag,
                aad: parsed.header,
            },
        )
        .map_err(|_| Error::DecryptionFailed)?;
    key.zeroize();

    Ok(plaintext)
}
