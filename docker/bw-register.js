#!/usr/bin/env node
/**
 * bw-register.js
 *
 * Programmatic Bitwarden/Vaultwarden account registration.
 * Uses only Node.js built-in modules (crypto, https, http) — no extra deps.
 *
 * The Bitwarden CLI does not have a `register` command. This script
 * performs the equivalent client-side crypto and HTTP POST to register a new
 * account directly against the Vaultwarden API.
 *
 * Registration flow (Vaultwarden 2026.x / Bitwarden post-2024):
 *   Step 1: POST /identity/accounts/register/send-verification-email
 *           When SMTP is not configured, Vaultwarden returns the verification
 *           JWT directly in the response body instead of sending an email.
 *   Step 2: POST /identity/accounts/register/finish
 *           Sends the JWT from step 1 along with the cryptographic material.
 *
 * Legacy fallback (older Vaultwarden):
 *   POST /api/accounts/register — single-step, no email verification token.
 *
 * Crypto chain (matches Bitwarden's official implementation; see bw-lib.js):
 *   masterKey  = PBKDF2-SHA256(password, email, 600000, 32)         (TEST_KDF=pbkdf2, default)
 *              | Argon2id(password, SHA-256(email), 64 MiB, 3, 4)   (TEST_KDF=argon2id)
 *   masterHash = PBKDF2-SHA256(masterKey, password, 1, 32) [base64]
 *   stretchKey = HKDF-Expand-SHA256("enc", 32) concat HKDF-Expand-SHA256("mac", 32)
 *   encSymKey  = AES-256-CBC-HMAC-SHA256(stretchKey, random 64 bytes)
 *   rsaPair    = RSA-2048, private key encrypted with encSymKey
 *
 * Environment: SETUP_EMAIL, SETUP_MASTER_PASSWORD, BW_SERVER_URL, and TEST_KDF
 * (pbkdf2, the default, or argon2id: 64 MiB, 3 iterations, parallelism 4).
 */

const crypto = require('crypto');
const http   = require('http');
const https  = require('https');
const lib    = require('./bw-lib.js');

const email     = process.env.SETUP_EMAIL;
const password  = process.env.SETUP_MASTER_PASSWORD;
const serverUrl = process.env.BW_SERVER_URL;

if (!email || !password || !serverUrl) {
  console.error('Required env vars: SETUP_EMAIL, SETUP_MASTER_PASSWORD, BW_SERVER_URL');
  process.exit(1);
}

function request(transport, options, body) {
  return new Promise((resolve, reject) => {
    const req = transport.request(options, (res) => {
      const chunks = [];
      res.on('data', (chunk) => chunks.push(chunk));
      res.on('end', () => resolve({ status: res.statusCode, body: Buffer.concat(chunks).toString() }));
    });
    req.on('error', reject);
    if (body) req.write(body);
    req.end();
  });
}

function makeOptions(url, method, body) {
  return {
    hostname: url.hostname,
    port: url.port || (url.protocol === 'https:' ? 443 : 80),
    path: url.pathname,
    method,
    headers: {
      'Content-Type': 'application/json',
      'Content-Length': body ? Buffer.byteLength(body) : 0,
    },
  };
}

async function register() {
  const kdf        = lib.registrationKdf();
  const masterKey  = lib.masterKey(password, email, kdf);
  const masterHash = lib.masterHash(masterKey, password);
  console.log(`[register] Account KDF: ${lib.describeKdf(kdf)}`);

  // Stretch the 32-byte master key into a 64-byte encryption+MAC key pair
  const stretchKey = lib.stretch(masterKey);

  // Generate a random 64-byte vault symmetric key and encrypt it
  const symKeyRaw = crypto.randomBytes(64);
  const encSymKey = lib.encryptCipherString(stretchKey, symKeyRaw);

  // Generate RSA-2048 key pair; encrypt the private key with the symmetric key
  const { privateKey, publicKey } = crypto.generateKeyPairSync('rsa', {
    modulusLength: 2048,
    publicKeyEncoding:  { type: 'spki',  format: 'der' },
    privateKeyEncoding: { type: 'pkcs8', format: 'der' },
  });
  const encPrivKey = lib.encryptCipherString(symKeyRaw, privateKey);

  const transport = serverUrl.startsWith('https:') ? https : http;

  // ── Step 1: request email verification token ──────────────────────────────
  // When SMTP is NOT configured (the test environment), Vaultwarden returns the
  // JWT verification token directly in the response body instead of emailing it.
  const verifyUrl  = new URL('/identity/accounts/register/send-verification-email', serverUrl);
  const verifyBody = JSON.stringify({ email, name: 'FerrowardenAdmin' });
  const step1 = await request(transport, makeOptions(verifyUrl, 'POST', verifyBody), verifyBody);

  if (step1.status === 404) {
    // Old Vaultwarden — try the legacy single-step endpoint
    console.log('[register] New API not found, trying legacy /api/accounts/register...');
    return legacyRegister(transport, email, masterHash, encSymKey, publicKey, encPrivKey, kdf);
  }

  if (step1.status !== 200) {
    console.error(`[register] send-verification-email HTTP ${step1.status}: ${step1.body}`);
    return 1;
  }

  // The response body is the JWT token: plain text in Vaultwarden 1.37, a JSON
  // string (in double quotes) in 1.36 and earlier.
  let verificationToken = step1.body.trim();
  if (verificationToken.startsWith('"')) {
    try { verificationToken = JSON.parse(verificationToken); } catch (_) { /* use as is */ }
  }
  if (!verificationToken) {
    console.error('[register] send-verification-email returned empty body');
    return 1;
  }
  console.log('[register] Received verification token from Vaultwarden.');

  // ── Step 2: finish registration with the crypto material ──────────────────
  const finishUrl  = new URL('/identity/accounts/register/finish', serverUrl);
  const finishBody = JSON.stringify({
    name: 'FerrowardenAdmin',
    email,
    emailVerificationToken: verificationToken,
    masterPasswordHash: masterHash,
    masterPasswordHint: '',
    kdfType: kdf.type,
    kdfIterations: kdf.iterations,
    kdfMemory: kdf.memory,
    kdfParallelism: kdf.parallelism,
    userSymmetricKey: encSymKey,
    userAsymmetricKeys: {
      publicKey: publicKey.toString('base64'),
      encryptedPrivateKey: encPrivKey,
    },
  });
  const step2 = await request(transport, makeOptions(finishUrl, 'POST', finishBody), finishBody);

  if (step2.status === 200 || step2.status === 204) {
    console.log('[register] Account registered successfully.');
    return 0;
  }
  if (step2.status === 400 && (step2.body.includes('already') || step2.body.includes('Username'))) {
    console.log('[register] Account already exists, continuing.');
    return 0;
  }
  console.error(`[register] register/finish HTTP ${step2.status}: ${step2.body}`);
  return 1;
}

async function legacyRegister(transport, emailAddr, masterHash, encSymKey, publicKey, encPrivKey, kdf) {
  const url  = new URL('/api/accounts/register', serverUrl);
  const body = JSON.stringify({
    name: 'FerrowardenAdmin',
    email: emailAddr,
    masterPasswordHash: masterHash,
    masterPasswordHint: '',
    key: encSymKey,
    kdf: kdf.type,
    kdfIterations: kdf.iterations,
    kdfMemory: kdf.memory,
    kdfParallelism: kdf.parallelism,
    keys: {
      publicKey: publicKey.toString('base64'),
      encryptedPrivateKey: encPrivKey,
    },
  });
  const res = await request(transport, makeOptions(url, 'POST', body), body);
  if (res.status === 200 || res.status === 204) {
    console.log('[register] Account registered via legacy endpoint.');
    return 0;
  }
  if (res.status === 400 && (res.body.includes('already') || res.body.includes('Username'))) {
    console.log('[register] Account already exists, continuing.');
    return 0;
  }
  console.error(`[register] Legacy endpoint HTTP ${res.status}: ${res.body}`);
  return 1;
}

register()
  .then((code) => process.exit(code))
  .catch((e) => {
    console.error('[register] Fatal error:', e.message);
    process.exit(1);
  });
