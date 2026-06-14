import test from "node:test";
import assert from "node:assert/strict";

// Test the built ESM entry point end-to-end through the native binding.
import {
  generateKeypair,
  seal,
  open,
  generateSigningKeypair,
  sign,
  verify,
} from "../dist/index.mjs";

test("generateKeypair returns hybrid public/secret blobs", async () => {
  const { publicKey, secretKey } = await generateKeypair();
  assert.ok(Buffer.isBuffer(publicKey));
  assert.ok(Buffer.isBuffer(secretKey));
  // PQCK magic on both blobs
  assert.deepEqual([...publicKey.subarray(0, 4)], [...Buffer.from("PQCK")]);
  assert.equal(publicKey.length, 6 + 32 + 1184);
  assert.equal(secretKey.length, 6 + 32 + 2400);
});

test("seal -> open roundtrip", async () => {
  const { publicKey, secretKey } = await generateKeypair();
  const msg = Buffer.from(JSON.stringify({ dni: "12345678Z", iban: "ES91..." }));
  const sealed = await seal(msg, publicKey);
  assert.deepEqual(await open(sealed, secretKey), msg);
});

test("accepts plain Uint8Array input (not just Buffer)", async () => {
  const { publicKey, secretKey } = await generateKeypair();
  const msg = new Uint8Array([1, 2, 3, 4, 5]);
  const sealed = await seal(msg, new Uint8Array(publicKey));
  const opened = await open(new Uint8Array(sealed), new Uint8Array(secretKey));
  assert.deepEqual([...opened], [...msg]);
});

test("sealed message has versioned PQCV header", async () => {
  const { publicKey } = await generateKeypair();
  const sealed = await seal(Buffer.from("x"), publicKey);
  assert.deepEqual([...sealed.subarray(0, 4)], [...Buffer.from("PQCV")]);
  assert.equal(sealed[4], 1); // version
  assert.equal(sealed[5], 1); // suite
});

test("wrong key fails to open", async () => {
  const a = await generateKeypair();
  const b = await generateKeypair();
  const sealed = await seal(Buffer.from("secret"), a.publicKey);
  await assert.rejects(() => open(sealed, b.secretKey));
});

test("tampered tag fails to open", async () => {
  const { publicKey, secretKey } = await generateKeypair();
  const sealed = await seal(Buffer.from("secret message"), publicKey);
  sealed[sealed.length - 1] ^= 0x01;
  await assert.rejects(() => open(sealed, secretKey));
});

test("public key rejected where secret expected", async () => {
  const { publicKey } = await generateKeypair();
  const sealed = await seal(Buffer.from("secret"), publicKey);
  await assert.rejects(() => open(sealed, publicKey));
});

// ---- signatures ----

test("sign -> verify roundtrip", async () => {
  const { publicKey, secretKey } = await generateSigningKeypair();
  const msg = Buffer.from("transfer 1000 EUR");
  const sig = await sign(msg, secretKey);
  assert.deepEqual([...sig.subarray(0, 4)], [...Buffer.from("PQCS")]);
  assert.equal(await verify(msg, sig, publicKey), true);
});

test("verify rejects tampered message", async () => {
  const { publicKey, secretKey } = await generateSigningKeypair();
  const sig = await sign(Buffer.from("original"), secretKey);
  assert.equal(await verify(Buffer.from("tampered"), sig, publicKey), false);
});

test("verify rejects wrong signer key", async () => {
  const a = await generateSigningKeypair();
  const b = await generateSigningKeypair();
  const sig = await sign(Buffer.from("msg"), a.secretKey);
  assert.equal(await verify(Buffer.from("msg"), sig, b.publicKey), false);
});

test("verify returns false on malformed signature", async () => {
  const { publicKey } = await generateSigningKeypair();
  assert.equal(await verify(Buffer.from("msg"), Buffer.from("garbage"), publicKey), false);
});
