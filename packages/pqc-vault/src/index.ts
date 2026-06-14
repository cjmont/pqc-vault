/**
 * pqc-vault — hybrid post-quantum encryption and signatures for Node.js.
 *
 * Hybrid (classical + post-quantum) construction using X25519 + ML-KEM-768 for
 * encryption and ML-DSA-65 for signatures, via the formally-verified libcrux
 * backend.
 *
 * All functions accept any `Uint8Array` (a Node `Buffer` is a `Uint8Array`, so
 * Buffers work too) and resolve to a `Buffer` (which is itself a `Uint8Array`).
 */

// The native addon loader is shipped alongside this file and kept external from
// the bundle, so its relative `require` of the platform `.node` stays correct.
import native from "../binding.js";

/** A hybrid keypair. Both fields are self-describing binary blobs. */
export interface KeyPair {
  /** Recipient public key (X25519 + ML-KEM-768), safe to share. */
  publicKey: Buffer;
  /** Recipient secret key (X25519 + ML-KEM-768). Keep secret. */
  secretKey: Buffer;
}

/** Accepts `Uint8Array` or Node `Buffer`. */
export type BytesInput = Uint8Array;

/**
 * Generate a fresh hybrid encryption keypair (X25519 + ML-KEM-768).
 */
export function generateKeypair(): Promise<KeyPair> {
  return native.generateKeypair();
}

/**
 * Hybrid-encrypt `data` for the holder of `recipientPublicKey`.
 *
 * Internally: ephemeral X25519 + ML-KEM-768 encapsulation, combined via
 * HKDF-SHA256, then AES-256-GCM over the payload. The output is a versioned,
 * self-describing binary message.
 */
export function seal(
  data: BytesInput,
  recipientPublicKey: BytesInput,
): Promise<Buffer> {
  return native.seal(data, recipientPublicKey);
}

/**
 * Decrypt a message produced by {@link seal} using `recipientSecretKey`.
 *
 * Rejects with a generic error on any failure (wrong key, tampered ciphertext,
 * tampered tag) without distinguishing the cause.
 */
export function open(
  ciphertext: BytesInput,
  recipientSecretKey: BytesInput,
): Promise<Buffer> {
  return native.open(ciphertext, recipientSecretKey);
}

// ---- Signatures (ML-DSA-65) ----

/**
 * Generate a fresh ML-DSA-65 signing keypair.
 */
export function generateSigningKeypair(): Promise<KeyPair> {
  return native.generateSigningKeypair();
}

/**
 * Sign `message` with an ML-DSA-65 signing secret key. Returns a versioned,
 * self-describing signature blob.
 */
export function sign(
  message: BytesInput,
  secretKey: BytesInput,
): Promise<Buffer> {
  return native.sign(message, secretKey);
}

/**
 * Verify a `signature` over `message` against a signing public key.
 *
 * Resolves to `true`/`false`. A malformed signature resolves to `false`; a
 * malformed public key rejects with an error.
 */
export function verify(
  message: BytesInput,
  signature: BytesInput,
  publicKey: BytesInput,
): Promise<boolean> {
  return native.verify(message, signature, publicKey);
}
