# pqc-vault

> 🔐 Cifrado y firmas **post-cuánticas híbridas** para Node.js, con una API
> sencilla estilo libsodium. Protege datos **hoy** contra el ataque
> "guardar ahora, descifrar después" (_harvest-now, decrypt-later_).
>
> 🔐 **Hybrid post-quantum** encryption and signatures for Node.js, with a
> simple libsodium-style API. Protect data **today** against
> _harvest-now, decrypt-later_.

**ML-KEM-768 + ML-DSA-65** · híbrido con X25519 / AES-256-GCM · 130/130 NIST ACVP test vectors

---

## 📦 Instalación / Install

```bash
npm install pqc-vault
```

No compila nada en tu máquina: trae binarios listos para Linux, macOS y Windows.
Funciona con ESM (`import`) y CommonJS (`require`), Node 18+.

_No compilation on your machine: prebuilt binaries for Linux, macOS and Windows.
Works with ESM (`import`) and CommonJS (`require`), Node 18+._

---

# 🇪🇸 Español

Todas las funciones aceptan un `Buffer` o un `Uint8Array` y devuelven un `Buffer`.
Como el cifrado trabaja con bytes, conviertes tu texto/objeto a bytes antes y
después.

### 1. Cifrar y descifrar un mensaje

```js
import { generateKeypair, seal, open } from "pqc-vault";

// Creas un par de claves: la pública para cifrar, la secreta para descifrar.
const { publicKey, secretKey } = await generateKeypair();

// Conviertes tu texto a bytes y lo ciframos con la clave pública.
const mensaje = Buffer.from("Hola, dato sensible");
const cifrado = await seal(mensaje, publicKey);

// Solo quien tiene la clave secreta puede recuperarlo.
const descifrado = await open(cifrado, secretKey);

console.log(descifrado.toString()); // "Hola, dato sensible"
```

### 2. Cifrar un objeto (por ejemplo, datos de un cliente)

```js
import { generateKeypair, seal, open } from "pqc-vault";

const { publicKey, secretKey } = await generateKeypair();

const cliente = { nombre: "Ada", iban: "ES91...", dni: "12345678Z" };

// objeto -> texto JSON -> bytes
const cifrado = await seal(Buffer.from(JSON.stringify(cliente)), publicKey);

// bytes -> texto JSON -> objeto
const recuperado = JSON.parse((await open(cifrado, secretKey)).toString());

console.log(recuperado.iban); // "ES91..."
```

### 3. Firmar y verificar

```js
import { generateSigningKeypair, sign, verify } from "pqc-vault";

// Claves de firma (distintas de las de cifrado).
const { publicKey, secretKey } = await generateSigningKeypair();

const orden = Buffer.from("transferir 1000 EUR");

// Firmas con la clave secreta.
const firma = await sign(orden, secretKey);

// Cualquiera verifica con la clave pública.
console.log(await verify(orden, firma, publicKey)); // true

// Si el mensaje cambia, la verificación da false.
const ordenFalsa = Buffer.from("transferir 9999 EUR");
console.log(await verify(ordenFalsa, firma, publicKey)); // false
```

### ¿Por qué "híbrido"?

Combina criptografía clásica (**X25519**) y post-cuántica (**ML-KEM-768**). Un
atacante tendría que romper **las dos** para leer tus datos. Así te proteges
incluso si en el futuro un ordenador cuántico rompe la criptografía clásica.

### Errores

Si `open` falla (clave equivocada o datos manipulados) lanza un error genérico,
**sin** decir el motivo exacto (para no dar pistas a un atacante). `verify`
devuelve `false` ante una firma inválida.

---

# 🇬🇧 English

Every function accepts a `Buffer` or a `Uint8Array` and returns a `Buffer`. Since
encryption works on bytes, convert your text/object to bytes before and after.

### 1. Encrypt and decrypt a message

```js
import { generateKeypair, seal, open } from "pqc-vault";

// Make a key pair: public key to encrypt, secret key to decrypt.
const { publicKey, secretKey } = await generateKeypair();

// Turn your text into bytes and encrypt with the public key.
const message = Buffer.from("Hello, sensitive data");
const encrypted = await seal(message, publicKey);

// Only the holder of the secret key can recover it.
const decrypted = await open(encrypted, secretKey);

console.log(decrypted.toString()); // "Hello, sensitive data"
```

### 2. Encrypt an object (e.g. customer data)

```js
import { generateKeypair, seal, open } from "pqc-vault";

const { publicKey, secretKey } = await generateKeypair();

const customer = { name: "Ada", iban: "ES91...", dni: "12345678Z" };

// object -> JSON text -> bytes
const encrypted = await seal(Buffer.from(JSON.stringify(customer)), publicKey);

// bytes -> JSON text -> object
const recovered = JSON.parse((await open(encrypted, secretKey)).toString());

console.log(recovered.iban); // "ES91..."
```

### 3. Sign and verify

```js
import { generateSigningKeypair, sign, verify } from "pqc-vault";

// Signing keys (different from the encryption keys).
const { publicKey, secretKey } = await generateSigningKeypair();

const order = Buffer.from("transfer 1000 EUR");

// Sign with the secret key.
const signature = await sign(order, secretKey);

// Anyone verifies with the public key.
console.log(await verify(order, signature, publicKey)); // true

// If the message changes, verification returns false.
const forged = Buffer.from("transfer 9999 EUR");
console.log(await verify(forged, signature, publicKey)); // false
```

### Why "hybrid"?

It combines classical (**X25519**) and post-quantum (**ML-KEM-768**)
cryptography. An attacker would have to break **both** to read your data — so you
stay protected even if a future quantum computer breaks classical crypto.

### Errors

If `open` fails (wrong key or tampered data) it throws a generic error **without**
revealing the exact reason (so an attacker learns nothing). `verify` returns
`false` for an invalid signature.

---

## 📚 Más / More

- API completa, esquema híbrido detallado y ejemplo ejecutable en el
  [repositorio](https://github.com/cjmont/pqc-vault).
- Reporte de vulnerabilidades: ver [SECURITY.md](https://github.com/cjmont/pqc-vault/blob/main/SECURITY.md).

## License

[Apache-2.0](https://github.com/cjmont/pqc-vault/blob/main/LICENSE)
