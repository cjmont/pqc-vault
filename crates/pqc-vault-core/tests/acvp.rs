//! Official NIST ACVP conformance vectors for the backend pqc-vault ships.
//!
//! These validate the *primitives* deterministically (the public pqc-vault API
//! uses the system RNG and cannot take ACVP seeds), against the official NIST
//! ACVP vectors for ML-KEM-768 and ML-DSA-65 (external/pure interface). Vectors
//! are vendored from usnistgov/ACVP-Server; see tests/vectors/manifest.json.

use libcrux_ml_dsa::ml_dsa_65;
use libcrux_ml_kem::mlkem768;
use serde_json::Value;
use sha2::{Digest, Sha256};

fn hx(v: &Value, key: &str) -> Vec<u8> {
    hex::decode(v[key].as_str().unwrap_or("")).expect("valid hex")
}

fn arr<const N: usize>(bytes: &[u8]) -> [u8; N] {
    bytes.try_into().expect("expected fixed length")
}

fn cases(json: &str) -> Vec<Value> {
    serde_json::from_str::<Vec<Value>>(json).expect("vector json array")
}

/// The vendored vector files must match the SHA-256 recorded in manifest.json,
/// so a silently-edited vector can never make conformance "pass".
#[test]
fn vendored_vectors_match_manifest() {
    let manifest: Value = serde_json::from_str(include_str!("vectors/manifest.json")).unwrap();
    let files: &[(&str, &str)] = &[
        (
            "ml-kem-768-keygen.json",
            include_str!("vectors/ml-kem-768-keygen.json"),
        ),
        (
            "ml-kem-768-encap.json",
            include_str!("vectors/ml-kem-768-encap.json"),
        ),
        (
            "ml-kem-768-decap.json",
            include_str!("vectors/ml-kem-768-decap.json"),
        ),
        (
            "ml-dsa-65-keygen.json",
            include_str!("vectors/ml-dsa-65-keygen.json"),
        ),
        (
            "ml-dsa-65-siggen.json",
            include_str!("vectors/ml-dsa-65-siggen.json"),
        ),
        (
            "ml-dsa-65-sigver.json",
            include_str!("vectors/ml-dsa-65-sigver.json"),
        ),
    ];
    for (name, content) in files {
        let got = hex::encode(Sha256::digest(content.as_bytes()));
        let want = manifest["files"][name]["sha256"].as_str().unwrap();
        assert_eq!(&got, want, "manifest sha256 mismatch for {name}");
    }
}

// ---------------- ML-KEM-768 ----------------

#[test]
fn ml_kem_768_keygen() {
    let v = cases(include_str!("vectors/ml-kem-768-keygen.json"));
    assert!(!v.is_empty());
    for t in &v {
        let mut seed = [0u8; 64];
        seed[..32].copy_from_slice(&hx(t, "d"));
        seed[32..].copy_from_slice(&hx(t, "z"));
        let kp = mlkem768::generate_key_pair(seed);
        assert_eq!(
            kp.pk().as_slice(),
            hx(t, "ek").as_slice(),
            "ek tc {}",
            t["tcId"]
        );
        assert_eq!(
            kp.sk().as_slice(),
            hx(t, "dk").as_slice(),
            "dk tc {}",
            t["tcId"]
        );
    }
    println!("ML-KEM-768 keyGen: {}/{} passing", v.len(), v.len());
}

#[test]
fn ml_kem_768_encapsulate() {
    let v = cases(include_str!("vectors/ml-kem-768-encap.json"));
    assert!(!v.is_empty());
    for t in &v {
        let ek = mlkem768::MlKem768PublicKey::from(arr::<1184>(&hx(t, "ek")));
        let m = arr::<32>(&hx(t, "m"));
        let (c, k) = mlkem768::encapsulate(&ek, m);
        assert_eq!(
            &c.as_slice()[..],
            hx(t, "c").as_slice(),
            "c tc {}",
            t["tcId"]
        );
        assert_eq!(k.as_slice(), hx(t, "k").as_slice(), "k tc {}", t["tcId"]);
    }
    println!("ML-KEM-768 encapsulate: {}/{} passing", v.len(), v.len());
}

#[test]
fn ml_kem_768_decapsulate() {
    let v = cases(include_str!("vectors/ml-kem-768-decap.json"));
    assert!(!v.is_empty());
    for t in &v {
        let dk = mlkem768::MlKem768PrivateKey::from(arr::<2400>(&hx(t, "dk")));
        let c = mlkem768::MlKem768Ciphertext::from(arr::<1088>(&hx(t, "c")));
        let k = mlkem768::decapsulate(&dk, &c);
        assert_eq!(k.as_slice(), hx(t, "k").as_slice(), "k tc {}", t["tcId"]);
    }
    println!("ML-KEM-768 decapsulate: {}/{} passing", v.len(), v.len());
}

// ---------------- ML-DSA-65 (external/pure) ----------------

#[test]
fn ml_dsa_65_keygen() {
    let v = cases(include_str!("vectors/ml-dsa-65-keygen.json"));
    assert!(!v.is_empty());
    for t in &v {
        let kp = ml_dsa_65::generate_key_pair(arr::<32>(&hx(t, "seed")));
        assert_eq!(
            kp.verification_key.as_ref().as_slice(),
            hx(t, "pk").as_slice(),
            "pk tc {}",
            t["tcId"]
        );
        assert_eq!(
            kp.signing_key.as_ref().as_slice(),
            hx(t, "sk").as_slice(),
            "sk tc {}",
            t["tcId"]
        );
    }
    println!("ML-DSA-65 keyGen: {}/{} passing", v.len(), v.len());
}

#[test]
fn ml_dsa_65_siggen() {
    let v = cases(include_str!("vectors/ml-dsa-65-siggen.json"));
    assert!(!v.is_empty());
    for t in &v {
        let sk = ml_dsa_65::MLDSA65SigningKey::new(arr::<4032>(&hx(t, "sk")));
        let msg = hx(t, "message");
        let ctx = hx(t, "context");
        let rnd = if t["deterministic"].as_bool().unwrap_or(false) {
            [0u8; 32]
        } else {
            arr::<32>(&hx(t, "rnd"))
        };
        let sig = ml_dsa_65::sign(&sk, &msg, &ctx, rnd).expect("sign");
        assert_eq!(
            sig.as_ref().as_slice(),
            hx(t, "signature").as_slice(),
            "sig tc {}",
            t["tcId"]
        );
    }
    println!("ML-DSA-65 sigGen: {}/{} passing", v.len(), v.len());
}

#[test]
fn ml_dsa_65_sigver() {
    let v = cases(include_str!("vectors/ml-dsa-65-sigver.json"));
    assert!(!v.is_empty());
    for t in &v {
        let pk = ml_dsa_65::MLDSA65VerificationKey::new(arr::<1952>(&hx(t, "pk")));
        let msg = hx(t, "message");
        let ctx = hx(t, "context");
        let sig_bytes = hx(t, "signature");
        let expected = t["testPassed"].as_bool().unwrap();

        // A malformed (wrong-length) signature can never verify.
        let got = if sig_bytes.len() == 3309 {
            let sig = ml_dsa_65::MLDSA65Signature::new(arr::<3309>(&sig_bytes));
            ml_dsa_65::verify(&pk, &msg, &ctx, &sig).is_ok()
        } else {
            false
        };
        assert_eq!(got, expected, "verify tc {}", t["tcId"]);
    }
    println!("ML-DSA-65 sigVer: {}/{} passing", v.len(), v.len());
}
