//! Node.js binding for pqc-vault via napi-rs.
//!
//! Every operation runs on the libuv thread pool (`AsyncTask`) so the JS event
//! loop is never blocked, and each function returns a real `Promise`. Inputs
//! accept any `Uint8Array` (Node `Buffer` included). Errors surface with the
//! core's generic messages — no secret material is ever exposed.

use napi::bindgen_prelude::*;
use napi::{Env, Task};
use napi_derive::napi;

fn to_napi(e: pqc_vault_core::Error) -> Error {
    // Core error messages are intentionally generic (no secrets, no oracle).
    Error::from_reason(e.to_string())
}

/// A hybrid keypair returned to JS as `{ publicKey, secretKey }`.
#[napi(object)]
pub struct KeyPair {
    pub public_key: Buffer,
    pub secret_key: Buffer,
}

pub struct GenerateKeypairTask;
impl Task for GenerateKeypairTask {
    type Output = (Vec<u8>, Vec<u8>);
    type JsValue = KeyPair;

    fn compute(&mut self) -> Result<Self::Output> {
        pqc_vault_core::generate_keypair().map_err(to_napi)
    }

    fn resolve(&mut self, _env: Env, output: Self::Output) -> Result<Self::JsValue> {
        Ok(KeyPair {
            public_key: output.0.into(),
            secret_key: output.1.into(),
        })
    }
}

pub struct SealTask {
    data: Vec<u8>,
    recipient_public_key: Vec<u8>,
}
impl Task for SealTask {
    type Output = Vec<u8>;
    type JsValue = Buffer;

    fn compute(&mut self) -> Result<Self::Output> {
        pqc_vault_core::seal(&self.data, &self.recipient_public_key).map_err(to_napi)
    }

    fn resolve(&mut self, _env: Env, output: Self::Output) -> Result<Self::JsValue> {
        Ok(output.into())
    }
}

pub struct OpenTask {
    ciphertext: Vec<u8>,
    recipient_secret_key: Vec<u8>,
}
impl Task for OpenTask {
    type Output = Vec<u8>;
    type JsValue = Buffer;

    fn compute(&mut self) -> Result<Self::Output> {
        pqc_vault_core::open(&self.ciphertext, &self.recipient_secret_key).map_err(to_napi)
    }

    fn resolve(&mut self, _env: Env, output: Self::Output) -> Result<Self::JsValue> {
        Ok(output.into())
    }
}

pub struct GenerateSigningKeypairTask;
impl Task for GenerateSigningKeypairTask {
    type Output = (Vec<u8>, Vec<u8>);
    type JsValue = KeyPair;

    fn compute(&mut self) -> Result<Self::Output> {
        pqc_vault_core::generate_signing_keypair().map_err(to_napi)
    }

    fn resolve(&mut self, _env: Env, output: Self::Output) -> Result<Self::JsValue> {
        Ok(KeyPair {
            public_key: output.0.into(),
            secret_key: output.1.into(),
        })
    }
}

pub struct SignTask {
    message: Vec<u8>,
    secret_key: Vec<u8>,
}
impl Task for SignTask {
    type Output = Vec<u8>;
    type JsValue = Buffer;

    fn compute(&mut self) -> Result<Self::Output> {
        pqc_vault_core::sign(&self.message, &self.secret_key).map_err(to_napi)
    }

    fn resolve(&mut self, _env: Env, output: Self::Output) -> Result<Self::JsValue> {
        Ok(output.into())
    }
}

pub struct VerifyTask {
    message: Vec<u8>,
    signature: Vec<u8>,
    public_key: Vec<u8>,
}
impl Task for VerifyTask {
    type Output = bool;
    type JsValue = bool;

    fn compute(&mut self) -> Result<Self::Output> {
        pqc_vault_core::verify(&self.message, &self.signature, &self.public_key).map_err(to_napi)
    }

    fn resolve(&mut self, _env: Env, output: Self::Output) -> Result<Self::JsValue> {
        Ok(output)
    }
}

/// Generate a hybrid (X25519 + ML-KEM-768) keypair.
#[napi(ts_return_type = "Promise<{ publicKey: Buffer, secretKey: Buffer }>")]
pub fn generate_keypair() -> AsyncTask<GenerateKeypairTask> {
    AsyncTask::new(GenerateKeypairTask)
}

/// Generate an ML-DSA-65 signing keypair.
#[napi(ts_return_type = "Promise<{ publicKey: Buffer, secretKey: Buffer }>")]
pub fn generate_signing_keypair() -> AsyncTask<GenerateSigningKeypairTask> {
    AsyncTask::new(GenerateSigningKeypairTask)
}

/// Sign a message with an ML-DSA-65 signing secret key. Returns the signature.
#[napi(ts_return_type = "Promise<Buffer>")]
pub fn sign(message: Uint8Array, secret_key: Uint8Array) -> AsyncTask<SignTask> {
    AsyncTask::new(SignTask {
        message: message.to_vec(),
        secret_key: secret_key.to_vec(),
    })
}

/// Verify a signature over a message against an ML-DSA-65 public key.
#[napi(ts_return_type = "Promise<boolean>")]
pub fn verify(
    message: Uint8Array,
    signature: Uint8Array,
    public_key: Uint8Array,
) -> AsyncTask<VerifyTask> {
    AsyncTask::new(VerifyTask {
        message: message.to_vec(),
        signature: signature.to_vec(),
        public_key: public_key.to_vec(),
    })
}

/// Hybrid-encrypt `data` to a recipient public key. Returns the sealed message.
#[napi(ts_return_type = "Promise<Buffer>")]
pub fn seal(data: Uint8Array, recipient_public_key: Uint8Array) -> AsyncTask<SealTask> {
    AsyncTask::new(SealTask {
        data: data.to_vec(),
        recipient_public_key: recipient_public_key.to_vec(),
    })
}

/// Decrypt a sealed message with the recipient secret key. Returns plaintext.
#[napi(ts_return_type = "Promise<Buffer>")]
pub fn open(ciphertext: Uint8Array, recipient_secret_key: Uint8Array) -> AsyncTask<OpenTask> {
    AsyncTask::new(OpenTask {
        ciphertext: ciphertext.to_vec(),
        recipient_secret_key: recipient_secret_key.to_vec(),
    })
}
