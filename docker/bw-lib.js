/**
 * bw-lib.js
 *
 * The Bitwarden client cryptography and HTTP plumbing shared by the test-stack
 * scripts (bw-register.js, bw-apikey.js, bw-seed.js, bw-seed-hidden.js).
 * Node.js built-in modules only (crypto, http, https). Test fixtures: never
 * use this for anything but the throwaway accounts of the test stack.
 *
 * Key derivation (what Bitwarden clients do, and src/ui/crypto.rs):
 *   PBKDF2-SHA256:  masterKey = PBKDF2(password, lowercased email, iterations, 32)
 *   Argon2id:       masterKey = Argon2id(password, salt = SHA-256(lowercased email),
 *                                memory = KiB (MiB * 1024), passes, parallelism, 32)
 *   masterHash      = base64(PBKDF2-SHA256(masterKey, password, 1, 32))
 *   stretched key   = HKDF-Expand-SHA256(masterKey, "enc", 32) || (..., "mac", 32)
 */

const crypto = require('crypto');
const http   = require('http');
const https  = require('https');

// ── KDF settings ──────────────────────────────────────────────────────────────

// 600,000 PBKDF2-SHA256 iterations: the current Bitwarden default. Registering
// with fewer makes current CLI releases silently upgrade the account's KDF on
// first login, which breaks any tool still assuming the old count.
const PBKDF2_ITERATIONS = 600000;

// Bitwarden's Argon2id defaults: 64 MiB, 3 iterations, 4 lanes.
const ARGON2_MEMORY_MIB = 64;
const ARGON2_ITERATIONS = 3;
const ARGON2_PARALLELISM = 4;

/** The KDF a new test account is registered with: TEST_KDF=pbkdf2 (default) or argon2id. */
function registrationKdf(name = process.env.TEST_KDF || 'pbkdf2') {
  switch (name.toLowerCase()) {
    case 'pbkdf2':
      return { type: 0, iterations: PBKDF2_ITERATIONS, memory: null, parallelism: null };
    case 'argon2id':
      return { type: 1, iterations: ARGON2_ITERATIONS, memory: ARGON2_MEMORY_MIB, parallelism: ARGON2_PARALLELISM };
    default:
      throw new Error(`unknown TEST_KDF ${JSON.stringify(name)} (pbkdf2 or argon2id)`);
  }
}

/** The KDF of an existing account, from a prelogin response (never assumed). */
function kdfFromPrelogin(d) {
  const pick = (a, b) => (d[a] !== undefined ? d[a] : d[b]);
  return {
    type: pick('kdf', 'Kdf'),
    iterations: pick('kdfIterations', 'KdfIterations'),
    memory: pick('kdfMemory', 'KdfMemory') ?? null,
    parallelism: pick('kdfParallelism', 'KdfParallelism') ?? null,
  };
}

function describeKdf(kdf) {
  return kdf.type === 1
    ? `Argon2id, ${kdf.memory} MiB, ${kdf.iterations} iterations, parallelism ${kdf.parallelism}`
    : `PBKDF2-SHA256, ${kdf.iterations} iterations`;
}

function pbkdf2(pass, salt, iterations, keylen) {
  return crypto.pbkdf2Sync(pass, salt, iterations, keylen, 'sha256');
}

function masterKey(password, email, kdf) {
  const normalized = email.trim().toLowerCase();
  if (kdf.type === 0) {
    return pbkdf2(Buffer.from(password), Buffer.from(normalized), kdf.iterations, 32);
  }
  if (kdf.type === 1) {
    if (typeof crypto.argon2Sync !== 'function') {
      throw new Error('crypto.argon2Sync is missing: Argon2id needs Node 24.7 or later');
    }
    return Buffer.from(crypto.argon2Sync('argon2id', {
      message: Buffer.from(password),
      nonce: crypto.createHash('sha256').update(normalized).digest(),
      parallelism: kdf.parallelism,
      tagLength: 32,
      memory: kdf.memory * 1024, // KiB
      passes: kdf.iterations,
    }));
  }
  throw new Error(`unsupported KDF type ${kdf.type}`);
}

function masterHash(mk, password) {
  return pbkdf2(mk, Buffer.from(password), 1, 32).toString('base64');
}

function hkdfExpand(prk, info, length) {
  const infoBytes = Buffer.from(info, 'utf8');
  const n = Math.ceil(length / 32);
  let okm = Buffer.alloc(0);
  let t   = Buffer.alloc(0);
  for (let i = 1; i <= n; i++) {
    const hmac = crypto.createHmac('sha256', prk);
    hmac.update(t);
    hmac.update(infoBytes);
    hmac.update(Buffer.from([i]));
    t   = hmac.digest();
    okm = Buffer.concat([okm, t]);
  }
  return okm.slice(0, length);
}

function stretch(mk) {
  return Buffer.concat([hkdfExpand(mk, 'enc', 32), hkdfExpand(mk, 'mac', 32)]);
}

// ── EncStrings ────────────────────────────────────────────────────────────────

// Decrypt Bitwarden CipherString type 2: "2.<iv_b64>|<ct_b64>|<mac_b64>"
// key: 64 bytes (first 32 = AES key, last 32 = HMAC key)
function decryptCipherString(key, cipherString) {
  const parts  = cipherString.split('.');
  const inner  = parts[1] || parts[0];
  const [ivB64, ctB64, macB64] = inner.split('|');
  const encKey = key.slice(0, 32);
  const macKey = key.slice(32, 64);
  const iv     = Buffer.from(ivB64,  'base64');
  const ct     = Buffer.from(ctB64,  'base64');
  const mac    = Buffer.from(macB64, 'base64');
  const expectedMac = crypto.createHmac('sha256', macKey).update(Buffer.concat([iv, ct])).digest();
  if (!crypto.timingSafeEqual(mac, expectedMac)) throw new Error('MAC verification failed');
  const decipher = crypto.createDecipheriv('aes-256-cbc', encKey, iv);
  return Buffer.concat([decipher.update(ct), decipher.final()]);
}

// Encrypt to Bitwarden CipherString type 2.
function encryptCipherString(key, plaintext) {
  const encKey = key.slice(0, 32);
  const macKey = key.slice(32, 64);
  const iv     = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv('aes-256-cbc', encKey, iv);
  const ct     = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const mac    = crypto.createHmac('sha256', macKey).update(Buffer.concat([iv, ct])).digest();
  return `2.${iv.toString('base64')}|${ct.toString('base64')}|${mac.toString('base64')}`;
}

// RSA-OAEP with SHA-1, what Bitwarden clients write as EncString type 4.
function rsaUnwrap(privateKey, encString) {
  const data = Buffer.from(encString.split('.')[1].split('|')[0], 'base64');
  return crypto.privateDecrypt(
    { key: privateKey, padding: crypto.constants.RSA_PKCS1_OAEP_PADDING, oaepHash: 'sha1' }, data);
}

function rsaWrap(publicKey, bytes) {
  return '4.' + crypto.publicEncrypt(
    { key: publicKey, padding: crypto.constants.RSA_PKCS1_OAEP_PADDING, oaepHash: 'sha1' }, bytes).toString('base64');
}

// ── HTTP ──────────────────────────────────────────────────────────────────────

function makeClient(serverUrl) {
  const transport = serverUrl.startsWith('https:') ? https : http;
  function request(method, path, body, headers = {}) {
    const url = new URL(path, serverUrl);
    const opts = {
      hostname: url.hostname,
      port: url.port || (url.protocol === 'https:' ? 443 : 80),
      path: url.pathname + url.search,
      method,
      headers: { ...headers },
    };
    if (body) opts.headers['Content-Length'] = Buffer.byteLength(body);
    return new Promise((resolve, reject) => {
      const req = transport.request(opts, (res) => {
        const chunks = [];
        res.on('data', (c) => chunks.push(c));
        res.on('end', () => resolve({ status: res.statusCode, body: Buffer.concat(chunks).toString() }));
      });
      req.on('error', reject);
      if (body) req.write(body);
      req.end();
    });
  }
  return { request };
}

/** prelogin: the account's KDF. */
async function prelogin(client, email) {
  const res = await client.request('POST', '/identity/accounts/prelogin', JSON.stringify({ email }),
    { 'Content-Type': 'application/json' });
  if (res.status !== 200) throw new Error(`prelogin failed (${res.status}): ${res.body}`);
  return kdfFromPrelogin(JSON.parse(res.body));
}

/**
 * Master-password login (password grant), as a test device. Returns the token
 * response plus the keys derived from the password: { token, data, kdf, mk,
 * hash, stretchKey }. The KDF is read from prelogin, never assumed.
 */
async function loginWithPassword(client, email, password, deviceName) {
  const kdf = await prelogin(client, email);
  const mk = masterKey(password, email, kdf);
  const hash = masterHash(mk, password);
  const params = new URLSearchParams({
    grant_type: 'password', username: email, password: hash,
    scope: 'api offline_access', client_id: 'web',
    deviceType: '6', deviceIdentifier: crypto.randomUUID(), deviceName,
  });
  const res = await client.request('POST', '/identity/connect/token', params.toString(), {
    'Content-Type': 'application/x-www-form-urlencoded',
  });
  if (res.status !== 200) throw new Error(`login failed (${res.status}): ${res.body}`);
  const data = JSON.parse(res.body);
  return { token: data.access_token, data, kdf, mk, hash, stretchKey: stretch(mk) };
}

module.exports = {
  PBKDF2_ITERATIONS, ARGON2_MEMORY_MIB, ARGON2_ITERATIONS, ARGON2_PARALLELISM,
  registrationKdf, kdfFromPrelogin, describeKdf,
  pbkdf2, masterKey, masterHash, hkdfExpand, stretch,
  decryptCipherString, encryptCipherString, rsaUnwrap, rsaWrap,
  makeClient, prelogin, loginWithPassword,
};
