// Example: protect a customer PII record against "harvest now, decrypt later".
//
// In a real project this import is simply:
//   import { generateKeypair, seal, open } from "pqc-vault";
// Here we import the locally-built package so the example runs from the repo.
import {
  generateKeypair,
  seal,
  open,
  generateSigningKeypair,
  sign,
  verify,
} from "../packages/pqc-vault/dist/index.mjs";

const enc = (obj) => Buffer.from(JSON.stringify(obj), "utf8");
const dec = (buf) => JSON.parse(Buffer.from(buf).toString("utf8"));

// 1. The recipient (e.g. your vault service) holds a long-term hybrid keypair.
const recipient = await generateKeypair();

// 2. A customer record with sensitive PII.
const customer = {
  id: "cust_8472",
  name: "Ada Lovelace",
  dni: "12345678Z",
  iban: "ES9121000418450200051332",
  balanceEUR: 42_000.5,
};

// 3. Seal it. The ciphertext is safe to store: even a future quantum computer
//    that recorded it today cannot decrypt it (X25519 + ML-KEM-768 hybrid).
const sealed = await seal(enc(customer), recipient.publicKey);
console.log(`Sealed ${sealed.length} bytes (versioned PQCV header).`);

// 4. Only the holder of the secret key can open it.
const recovered = dec(await open(sealed, recipient.secretKey));
console.log("Recovered IBAN:", recovered.iban);

// 5. Tampering is detected (AES-256-GCM tag + header bound as AAD).
const tampered = Buffer.from(sealed);
tampered[tampered.length - 1] ^= 0x01;
try {
  await open(tampered, recipient.secretKey);
  console.error("FAIL: tampered ciphertext opened");
  process.exit(1);
} catch {
  console.log("Tampered ciphertext rejected (as expected).");
}

// 6. Post-quantum signatures (ML-DSA-65): prove integrity/authenticity of, e.g.,
//    a transaction order.
const signer = await generateSigningKeypair();
const order = enc({ from: "cust_8472", toIban: "DE89...", amountEUR: 1000 });
const signature = await sign(order, signer.secretKey);
console.log("Signature valid:", await verify(order, signature, signer.publicKey));

// A modified order no longer verifies.
const forged = enc({ from: "cust_8472", toIban: "DE89...", amountEUR: 9999 });
console.log(
  "Forged order valid:",
  await verify(forged, signature, signer.publicKey),
);
