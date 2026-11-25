#!/usr/bin/env node
/**
 * Generates src/vault/native/testdata/vectors.json: known-answer vectors for
 * the native vault backend's cryptography.
 *
 * The vectors are produced by Node's `crypto` module (OpenSSL), an
 * implementation independent of the RustCrypto code under test, from fixed
 * keys and IVs, using only the primitives the formats are made of:
 * AES-256-CBC, HMAC-SHA256, HKDF-Expand and RSA-OAEP. They are NOT taken from
 * the Bitwarden SDK or its test suites (docs/native-vault.md).
 *
 * The RSA key is a throwaway 2048-bit key generated for these tests only; it
 * protects nothing and appears in no vault.
 *
 * Regenerate (the output is committed):
 *   docker run --rm -v "$PWD":/w -w /w node:26-slim \
 *     node tests/native-vectors/gen.js > src/vault/native/testdata/vectors.json
 *
 * Only the RSA ciphertexts and the RSA key differ between runs (OAEP padding
 * is randomised); keep the committed file unless a vector needs to change.
 */
const crypto = require('crypto');

const hex = (b) => Buffer.from(b).toString('hex');
const b64 = (b) => Buffer.from(b).toString('base64');

// Deterministic key bytes: byte i = (i * 7 + seed) mod 256.
const keyBytes = (seed, n = 64) => Buffer.from(Array.from({ length: n }, (_, i) => (i * 7 + seed) & 0xff));

function encrypt2(key, iv, plain) {
  const c = crypto.createCipheriv('aes-256-cbc', key.subarray(0, 32), iv);
  const ct = Buffer.concat([c.update(plain), c.final()]);
  const mac = crypto.createHmac('sha256', key.subarray(32)).update(Buffer.concat([iv, ct])).digest();
  return `2.${b64(iv)}|${b64(ct)}|${b64(mac)}`;
}

// HKDF-Expand (RFC 5869) with SHA-256, built from HMAC directly.
function hkdfExpand(prk, info, len) {
  let t = Buffer.alloc(0);
  let okm = Buffer.alloc(0);
  for (let i = 1; okm.length < len; i++) {
    t = crypto.createHmac('sha256', prk).update(Buffer.concat([t, Buffer.from(info), Buffer.from([i])])).digest();
    okm = Buffer.concat([okm, t]);
  }
  return okm.subarray(0, len);
}

const out = {};

// ── Type 2 ────────────────────────────────────────────────────────────────────
const key = keyBytes(11);
out.type2 = { key: hex(key), cases: [] };
const plains = ['', 'a', 'password', '0123456789abcdef', '0123456789abcdefX', 'p@ss w0rd! ü€ 中', 'N'.repeat(1000)];
plains.forEach((p, n) => {
  const iv = keyBytes(100 + n, 16);
  out.type2.cases.push({ plain_utf8: p, iv: hex(iv), enc: encrypt2(key, iv, Buffer.from(p, 'utf8')) });
});

// ── HKDF stretch of a 32-byte master key ──────────────────────────────────────
const master = keyBytes(3, 32);
out.stretch = {
  master_key: hex(master),
  enc: hex(hkdfExpand(master, 'enc', 32)),
  mac: hex(hkdfExpand(master, 'mac', 32)),
};

// ── RSA-OAEP ──────────────────────────────────────────────────────────────────
const kp = crypto.generateKeyPairSync('rsa', {
  modulusLength: 2048,
  publicKeyEncoding: { type: 'spki', format: 'der' },
  privateKeyEncoding: { type: 'pkcs8', format: 'der' },
});
const pub = crypto.createPublicKey({ key: kp.publicKey, format: 'der', type: 'spki' });
const payload = keyBytes(42, 64);
const rsaEnc = (hash) => b64(crypto.publicEncrypt({ key: pub, padding: crypto.constants.RSA_PKCS1_OAEP_PADDING, oaepHash: hash }, payload));
out.rsa = {
  note: 'throwaway test key, protects nothing',
  pkcs8_der_b64: b64(kp.privateKey),
  payload: hex(payload),
  sha1: `4.${rsaEnc('sha1')}`,
  sha256: `3.${rsaEnc('sha256')}`,
};

process.stdout.write(JSON.stringify(out, null, 2) + '\n');
