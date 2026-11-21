#!/usr/bin/env node
/**
 * bw-seed.js
 *
 * Idempotent Vaultwarden credential seeder using direct API calls.
 * Uses only Node.js built-in modules (crypto, https, http, fs) — no extra deps.
 *
 * Written when the pinned Bitwarden CLI (2023.12.1) could not create items on
 * current Vaultwarden (the API requires an `encryptedFor` field on every
 * cipher). Kept so test fixtures do not depend on CLI item-creation
 * behaviour. This script implements seeding entirely via HTTP, performing
 * the crypto itself. HTTPS targets trust NODE_EXTRA_CA_CERTS.
 *
 * Flow:
 *   1. Derive master key and hash (PBKDF2)
 *   2. Obtain access token from /identity/connect/token
 *   3. Decrypt the vault symmetric key from the Key field in the token response
 *   4. List existing items (GET /api/ciphers) for idempotency
 *   5. For each credential in credentials.json:
 *      - Encrypt name, password and URIs with the vault key
 *      - POST /api/ciphers with encryptedFor = user UUID (or PUT to
 *        update an existing item whose URIs differ from the seed file)
 *
 * Environment:
 *   BW_SERVER_URL          — Vaultwarden base URL
 *   SETUP_EMAIL            — Vault account email
 *   SETUP_MASTER_PASSWORD  — Vault master password
 *   CREDENTIALS_FILE       — Path to credentials.json (default: /seed/credentials.json)
 */

const crypto = require('crypto');
const http   = require('http');
const https  = require('https');
const fs     = require('fs');

const serverUrl         = process.env.BW_SERVER_URL;
const email             = process.env.SETUP_EMAIL;
const password          = process.env.SETUP_MASTER_PASSWORD;
const credentialsFile   = process.env.CREDENTIALS_FILE || '/seed/credentials.json';

if (!serverUrl || !email || !password) {
  console.error('Required env vars: BW_SERVER_URL, SETUP_EMAIL, SETUP_MASTER_PASSWORD');
  process.exit(1);
}

// ── Crypto helpers ────────────────────────────────────────────────────────────

function pbkdf2(pass, salt, iterations, keylen) {
  return crypto.pbkdf2Sync(pass, salt, iterations, keylen, 'sha256');
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

// Encrypt to Bitwarden CipherString type 2: "2.<iv_b64>|<ct_b64>|<mac_b64>"
// key: 64 bytes (first 32 = AES key, last 32 = HMAC key)
function encryptCipherString(key, plaintext) {
  const encKey = key.slice(0, 32);
  const macKey = key.slice(32, 64);
  const iv     = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv('aes-256-cbc', encKey, iv);
  const ct     = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const mac    = crypto.createHmac('sha256', macKey).update(Buffer.concat([iv, ct])).digest();
  return `2.${iv.toString('base64')}|${ct.toString('base64')}|${mac.toString('base64')}`;
}

// ── HTTP helpers ──────────────────────────────────────────────────────────────

const transport = serverUrl.startsWith('https:') ? https : http;

function request(method, path, body, headers = {}) {
  const url = new URL(path, serverUrl);
  const opts = {
    hostname: url.hostname,
    port: url.port || (url.protocol === 'https:' ? 443 : 80),
    path: url.pathname + url.search,
    method,
    headers,
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

function post(path, body, token) {
  const headers = { 'Content-Type': 'application/json' };
  if (token) headers['Authorization'] = `Bearer ${token}`;
  return request('POST', path, body, headers);
}

function get(path, token) {
  const headers = { 'Authorization': `Bearer ${token}` };
  return request('GET', path, null, headers);
}

// ── Main ──────────────────────────────────────────────────────────────────────

async function seed() {
  const credentials = JSON.parse(fs.readFileSync(credentialsFile, 'utf8'));

  // 1. Derive master key and hash, using the account's current KDF settings.
  //    Never assume an iteration count: current Bitwarden clients raise it
  //    (e.g. 100,000 -> 600,000) automatically after login.
  const pre = await post('/identity/accounts/prelogin', JSON.stringify({ email }));
  if (pre.status !== 200) {
    console.error(`[seed] prelogin failed (${pre.status}): ${pre.body}`);
    return 1;
  }
  const preData = JSON.parse(pre.body);
  const kdfType = preData.kdf ?? preData.Kdf;
  const kdfIterations = preData.kdfIterations ?? preData.KdfIterations;
  if (kdfType !== 0) {
    console.error(`[seed] Unsupported KDF type ${kdfType} (only PBKDF2-SHA256 is implemented)`);
    return 1;
  }
  const masterKey  = pbkdf2(Buffer.from(password), Buffer.from(email.toLowerCase()), kdfIterations, 32);
  const masterHash = pbkdf2(masterKey, Buffer.from(password), 1, 32).toString('base64');

  // 2. Stretch the master key (same as during registration)
  const stretchKey = Buffer.concat([
    hkdfExpand(masterKey, 'enc', 32),
    hkdfExpand(masterKey, 'mac', 32),
  ]);

  // 3. Obtain access token (must be form-encoded, not JSON)
  const deviceId = crypto.randomUUID();
  const params   = new URLSearchParams({
    grant_type: 'password', username: email, password: masterHash,
    scope: 'api offline_access', client_id: 'web',
    deviceType: '6', deviceIdentifier: deviceId, deviceName: 'ferrowarden-seeder',
  });
  const tokenResForm = await request('POST', '/identity/connect/token', params.toString(), {
    'Content-Type': 'application/x-www-form-urlencoded',
    'Content-Length': Buffer.byteLength(params.toString()),
  });

  if (tokenResForm.status !== 200) {
    console.error(`[seed] Auth failed (${tokenResForm.status}): ${tokenResForm.body}`);
    return 1;
  }

  const tokenData   = JSON.parse(tokenResForm.body);
  const accessToken = tokenData.access_token;
  const encKeyStr   = tokenData.Key || tokenData.key;

  if (!accessToken || !encKeyStr) {
    console.error('[seed] Missing access_token or Key in auth response');
    return 1;
  }

  // Decode user UUID from JWT (no verification needed — we issued this request)
  const jwtPayload = JSON.parse(Buffer.from(accessToken.split('.')[1], 'base64').toString());
  const userUuid   = jwtPayload.sub;

  // 4. Decrypt the vault symmetric key
  const symKey = decryptCipherString(stretchKey, encKeyStr);

  console.log(`[seed] Authenticated as ${email} (${userUuid})`);

  // 5. List existing items for idempotency
  const listRes = await get('/api/ciphers', accessToken);
  if (listRes.status !== 200) {
    console.error(`[seed] Listing existing items failed (${listRes.status}): ${listRes.body}`);
    return 1;
  }
  // name -> [{ id, uris: [decrypted URI strings] }, ...]
  const existingAll = new Map();
  const ciphers = JSON.parse(listRes.body);
  // Older Vaultwarden returns {Data:[...]}, current releases {data:[...]},
  // some proxies a bare array. Missing this made every run re-create items.
  const items = Array.isArray(ciphers?.data) ? ciphers.data
              : Array.isArray(ciphers?.Data) ? ciphers.Data
              : Array.isArray(ciphers)       ? ciphers
              : [];
  for (const c of items) {
    if (c.deletedDate || c.DeletedDate) continue; // already in the trash
    try {
      const name  = decryptCipherString(symKey, c.Name || c.name).toString('utf8');
      const login = c.Login || c.login || {};
      const uris  = (login.Uris || login.uris || [])
        .map((u) => u.Uri || u.uri)
        .filter(Boolean)
        .map((u) => decryptCipherString(symKey, u).toString('utf8'));
      if (!existingAll.has(name)) existingAll.set(name, []);
      existingAll.get(name).push({ id: c.Id || c.id, uris });
    } catch (_) { /* skip undecryptable items */ }
  }

  // Ferrowarden refuses ambiguous names, so the seed must leave exactly one
  // item per seeded name. Move extra copies (from earlier non-idempotent runs)
  // to the trash — only for names this seed file manages.
  const sameUris = (a, b) => a.length === b.length && a.every((u, i) => u === b[i]);
  const existing = new Map();
  let trashed = 0;
  for (const cred of credentials) {
    const copies = existingAll.get(cred.name) || [];
    if (copies.length === 0) continue;
    const want = cred.uris || [];
    const keep = copies.find((c) => sameUris(c.uris, want)) || copies[0];
    existing.set(cred.name, keep);
    for (const extra of copies.filter((c) => c !== keep)) {
      const res = await request('PUT', `/api/ciphers/${extra.id}/delete`, null, {
        'Authorization': `Bearer ${accessToken}`,
      });
      if (res.status === 200 || res.status === 204) {
        console.log(`  trashed duplicate: ${cred.name}`);
        trashed++;
      } else {
        console.error(`  ERROR trashing duplicate ${cred.name} (${res.status}): ${res.body}`);
      }
    }
  }

  // 6. Create missing credentials; update existing ones whose URIs differ.
  // Ferrowarden only sends a credential to hosts in its item's URIs, so stale
  // URIs from an older seed would break the integration tests.
  let created = 0;
  let updated = 0;
  let skipped = 0;
  let failed  = 0;

  for (const cred of credentials) {
    const { name, value, note = '', uris = [] } = cred;
    const current = existing.get(name);

    if (current && sameUris(current.uris, uris)) {
      console.log(`  skip (exists): ${name}`);
      skipped++;
      continue;
    }

    const encName     = encryptCipherString(symKey, Buffer.from(name,  'utf8'));
    const encPassword = encryptCipherString(symKey, Buffer.from(value, 'utf8'));
    const encNotes    = note
      ? encryptCipherString(symKey, Buffer.from(note, 'utf8'))
      : null;
    const encUris     = uris.length
      ? uris.map((u) => ({ uri: encryptCipherString(symKey, Buffer.from(u, 'utf8')), match: null }))
      : null;

    const cipher = {
      type: 1,
      name: encName,
      notes: encNotes,
      reprompt: 0,
      encryptedFor: userUuid,
      login: {
        uris: encUris,
        username: null,
        password: encPassword,
        passwordRevisionDate: null,
        totp: null,
        autofillOnPageLoad: null,
      },
    };

    if (current) {
      const res = await request('PUT', `/api/ciphers/${current.id}`, JSON.stringify(cipher), {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${accessToken}`,
      });
      if (res.status === 200) {
        console.log(`  updated URIs: ${name}`);
        updated++;
      } else {
        console.error(`  ERROR updating ${name} (${res.status}): ${res.body}`);
        failed++;
      }
      continue;
    }

    const createRes = await post('/api/ciphers', JSON.stringify(cipher), accessToken);
    if (createRes.status === 200 || createRes.status === 201) {
      console.log(`  created: ${name}`);
      created++;
    } else {
      console.error(`  ERROR creating ${name} (${createRes.status}): ${createRes.body}`);
      failed++;
    }
  }

  console.log(`\nDone. Created: ${created}, Updated: ${updated}, Trashed duplicates: ${trashed}, Skipped: ${skipped}, Failed: ${failed}`);
  return failed > 0 ? 1 : 0;
}

seed()
  .then((code) => process.exit(code))
  .catch((e) => {
    console.error('[seed] Fatal error:', e.message);
    process.exit(1);
  });
