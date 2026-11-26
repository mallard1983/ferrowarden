#!/usr/bin/env node
/**
 * bw-read-item.js
 *
 * The independent reader of the credential-create tests (docs/native-vault.md,
 * "How the write path is verified"). It logs in to Vaultwarden as the test
 * account with the master password, finds the item named ITEM_NAME in
 * /api/sync, decrypts it with Node's `crypto` (bw-lib.js: no Ferrowarden code,
 * no Rust), and prints ONE line of JSON:
 *
 *   {
 *     "found": true, "count": 1,
 *     "passwordSha256": "<hex sha-256 of the password>",   // never the password
 *     "passwordLength": 32,
 *     "username": "admin",
 *     "uris": ["https://..."],
 *     "checksumsValid": true,       // every uriChecksum is base64(SHA-256(uri))
 *     "fieldNames": ["ferrowarden_created_by", ...],
 *     "createdBy": "<value of ferrowarden_created_by>",
 *     "approvalField": "required" | null,
 *     "organizationId": "...", "collections": ["Ferrowarden managed"],
 *     "type": 1, "hasItemKey": true, "totp": null, "notes": null
 *   }
 *
 * The password itself is never printed: only its SHA-256 (the test compares it
 * with the hash of what the target received). Test fixtures only: this logs in
 * with the master password of the throwaway test account.
 *
 * Environment:
 *   BW_SERVER_URL          Vaultwarden base URL
 *   SETUP_EMAIL            the test account
 *   SETUP_MASTER_PASSWORD  its master password (or SETUP_MASTER_PASSWORD_FILE: a file with it)
 *   ITEM_NAME              the item to read (exact name)
 */

const crypto = require('crypto');
const fs     = require('fs');
const lib    = require('./bw-lib.js');

const serverUrl = process.env.BW_SERVER_URL;
const email     = process.env.SETUP_EMAIL;
// The password comes from a Docker secret file (docker-compose.test.yml), or
// directly from the environment.
const password  = process.env.SETUP_MASTER_PASSWORD ||
  (process.env.SETUP_MASTER_PASSWORD_FILE
    ? fs.readFileSync(process.env.SETUP_MASTER_PASSWORD_FILE, 'utf8').trim()
    : undefined);
const itemName  = process.env.ITEM_NAME;
const CLIENT_HEADERS = { 'Bitwarden-Client-Name': 'cli', 'Bitwarden-Client-Version': '2024.12.0' };

if (!serverUrl || !email || !password || !itemName) {
  console.error('Required env vars: BW_SERVER_URL, SETUP_EMAIL, SETUP_MASTER_PASSWORD(_FILE), ITEM_NAME');
  process.exit(2);
}

const { request } = lib.makeClient(serverUrl);
const dec = (key, s) => (s ? lib.decryptCipherString(key, s).toString('utf8') : null);

async function main() {
  const login = await lib.loginWithPassword({ request }, email, password, 'ferrowarden-reader');
  const token = login.data.access_token;
  const encKey = login.data.Key || login.data.key;
  const encPriv = login.data.PrivateKey || login.data.privateKey;
  const userKey = lib.decryptCipherString(login.stretchKey, encKey);
  const privateKey = crypto.createPrivateKey({
    key: lib.decryptCipherString(userKey, encPriv), format: 'der', type: 'pkcs8',
  });

  const res = await request('GET', '/api/sync?excludeDomains=true', null,
    { Authorization: `Bearer ${token}`, ...CLIENT_HEADERS });
  if (res.status !== 200) throw new Error(`sync failed (${res.status})`);
  const sync = JSON.parse(res.body);

  const orgKeys = new Map();
  for (const o of (sync.profile.organizations || [])) {
    if (o.key) {
      try { orgKeys.set(o.id, lib.rsaUnwrap(privateKey, o.key)); } catch (_) { /* not ours */ }
    }
  }
  const collectionNames = new Map();
  for (const c of (sync.collections || [])) {
    const k = orgKeys.get(c.organizationId);
    if (k) { try { collectionNames.set(c.id, dec(k, c.name)); } catch (_) { /* skip */ } }
  }

  const found = [];
  for (const c of (sync.ciphers || [])) {
    if (c.deletedDate) continue;
    const base = c.organizationId ? orgKeys.get(c.organizationId) : userKey;
    if (!base) continue;
    let key;
    let name;
    try {
      key = c.key ? lib.decryptCipherString(base, c.key) : base;
      name = dec(key, c.name);
    } catch (_) { continue; }
    if (name !== itemName) continue;

    const l = c.login || {};
    const password_ = dec(key, l.password);
    const uris = (l.uris || []).filter((u) => u.uri).map((u) => ({
      uri: dec(key, u.uri),
      checksum: u.uriChecksum ? dec(key, u.uriChecksum) : null,
    }));
    const fields = (c.fields || []).map((f) => ({ name: dec(key, f.name), value: dec(key, f.value) }));
    const field = (n) => (fields.find((f) => f.name === n) || {}).value ?? null;
    found.push({
      passwordSha256: password_ === null ? null : crypto.createHash('sha256').update(password_, 'utf8').digest('hex'),
      passwordLength: password_ === null ? null : [...password_].length,
      username: dec(key, l.username),
      uris: uris.map((u) => u.uri),
      checksumsValid: uris.length > 0 && uris.every((u) =>
        u.checksum === crypto.createHash('sha256').update(u.uri, 'utf8').digest('base64')),
      fieldNames: fields.map((f) => f.name),
      createdBy: field('ferrowarden_created_by'),
      approvalField: field('ferrowarden_approval'),
      organizationId: c.organizationId || null,
      collections: (c.collectionIds || []).map((id) => collectionNames.get(id) || id),
      type: c.type,
      hasItemKey: !!c.key,
      totp: dec(key, l.totp),
      notes: dec(key, c.notes),
    });
  }
  const out = found.length === 1
    ? { found: true, count: 1, ...found[0] }
    : { found: found.length > 0, count: found.length };
  console.log(JSON.stringify(out));
}

main().catch((e) => {
  console.error(`[read-item] ${e.message}`);
  process.exit(1);
});
