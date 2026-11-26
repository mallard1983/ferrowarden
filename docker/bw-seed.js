#!/usr/bin/env node
/**
 * bw-seed.js
 *
 * Idempotent Vaultwarden credential seeder using direct API calls.
 * Uses only Node.js built-in modules (crypto, https, http, fs) - no extra deps
 * and no `bw` CLI. It performs the Bitwarden client cryptography itself, so
 * the fixtures do not depend on any CLI's item-creation behaviour, and it can
 * write the shapes the native vault backend must read: per-item keys,
 * organisation items, and the item types Ferrowarden does not offer.
 *
 * Flow:
 *   1. Derive master key and hash (PBKDF2 or Argon2id, as the account has
 *      it), log in, decrypt the user key and
 *      the RSA private key.
 *   2. Sync, and find or create the test organisation and its collection
 *      (only when a seed entry asks for `org`).
 *   3. List existing items (decrypting their names with the right key) for
 *      idempotency.
 *   4. For each entry of credentials.json: create it, or update it when its
 *      URIs differ, or skip it.
 *
 * Seed entry format (tests/seed/credentials.json):
 *   name, value (password), note, uris           - as before
 *   uris: strings, or { uri, match } objects      - match: 0 domain .. 5 never
 *   type: "login" (default) | "secure_note" | "card" | "identity" | "ssh"
 *   username, totp                                - login only
 *   reprompt: true                                - master password re-prompt
 *   fields: [{ name, value, type: "text"|"hidden"|"boolean"|"linked", linked: "username"|"password" }]
 *   cipher_key: true                              - give the item its own key
 *   org: true                                     - put it in the test organisation
 *   empty_string: ["username", ...]               - encrypt "" (not null) for these
 *   archived: true                                - archive it (if the server can)
 *   card / identity / ssh: { property: value }    - the other item types' data
 *
 * Environment:
 *   BW_SERVER_URL          - Vaultwarden base URL
 *   SETUP_EMAIL            - Vault account email
 *   SETUP_MASTER_PASSWORD  - Vault master password
 *   CREDENTIALS_FILE       - Path to credentials.json (default: /seed/credentials.json)
 */

const crypto = require('crypto');
const fs     = require('fs');

const serverUrl         = process.env.BW_SERVER_URL;
const email             = process.env.SETUP_EMAIL;
const password          = process.env.SETUP_MASTER_PASSWORD;
const credentialsFile   = process.env.CREDENTIALS_FILE || '/seed/credentials.json';

const ORG_NAME = 'ferrowarden-test-org';
// Sent so the sync includes every item type (SSH keys need >= 2024.12.0).
const CLIENT_HEADERS = { 'Bitwarden-Client-Name': 'cli', 'Bitwarden-Client-Version': '2024.12.0' };

if (!serverUrl || !email || !password) {
  console.error('Required env vars: BW_SERVER_URL, SETUP_EMAIL, SETUP_MASTER_PASSWORD');
  process.exit(1);
}

// -- Crypto helpers (bw-lib.js) ------------------------------------------------

const lib = require('./bw-lib.js');
const { decryptCipherString, encryptCipherString, rsaUnwrap } = lib;

// -- HTTP helpers ----------------------------------------------------------------

const { request } = lib.makeClient(serverUrl);

let accessToken = null;
const authHeaders = (extra = {}) => ({ Authorization: `Bearer ${accessToken}`, ...CLIENT_HEADERS, ...extra });

const postJson = (path, obj) =>
  request('POST', path, JSON.stringify(obj), authHeaders({ 'Content-Type': 'application/json' }));
const putJson = (path, obj) =>
  request('PUT', path, JSON.stringify(obj), authHeaders({ 'Content-Type': 'application/json' }));
const getAuthed = (path) => request('GET', path, null, authHeaders());

// -- Main ----------------------------------------------------------------------

async function seed() {
  const credentials = JSON.parse(fs.readFileSync(credentialsFile, 'utf8'));

  // 1. Log in with the account's current KDF settings, read from prelogin.
  //    Never assume an iteration count (current Bitwarden clients raise it
  //    automatically after login) or the KDF itself: the account may be
  //    PBKDF2 or Argon2id (TEST_KDF at registration, bw-register.js).
  let login;
  try {
    login = await lib.loginWithPassword({ request }, email, password, 'ferrowarden-seeder');
  } catch (e) {
    console.error(`[seed] ${e.message}`);
    return 1;
  }
  console.log(`[seed] Account KDF: ${lib.describeKdf(login.kdf)}`);
  const stretchKey  = login.stretchKey;
  const tokenData   = login.data;
  accessToken       = tokenData.access_token;
  const encKeyStr   = tokenData.Key || tokenData.key;
  const encPrivStr  = tokenData.PrivateKey || tokenData.privateKey;

  if (!accessToken || !encKeyStr) {
    console.error('[seed] Missing access_token or Key in auth response');
    return 1;
  }

  // Decode user UUID from JWT (no verification needed - we issued this request)
  const jwtPayload = JSON.parse(Buffer.from(accessToken.split('.')[1], 'base64').toString());
  const userUuid   = jwtPayload.sub;

  // 4. Decrypt the vault symmetric key and the RSA private key
  const symKey = decryptCipherString(stretchKey, encKeyStr);
  const privateKey = encPrivStr
    ? crypto.createPrivateKey({ key: decryptCipherString(symKey, encPrivStr), format: 'der', type: 'pkcs8' })
    : null;

  console.log(`[seed] Authenticated as ${email} (${userUuid})`);

  const syncVault = async () => {
    const res = await getAuthed('/api/sync?excludeDomains=true');
    if (res.status !== 200) throw new Error(`sync failed (${res.status})`);
    return JSON.parse(res.body);
  };
  let sync = await syncVault();

  // 5. The test organisation, created on demand.
  const orgNeeded = credentials.some((c) => c.org);
  const findOrg = (s) => (s.profile.organizations || []).find((o) => o.name === ORG_NAME);
  let org = findOrg(sync);
  if (orgNeeded && !org) {
    if (!privateKey) { console.error('[seed] account has no RSA key'); return 1; }
    const orgKeyBytes = crypto.randomBytes(64);
    const pub = crypto.createPublicKey(privateKey);
    const encOrgKey = lib.rsaWrap(pub, orgKeyBytes);
    const kp = crypto.generateKeyPairSync('rsa', {
      modulusLength: 2048,
      publicKeyEncoding: { type: 'spki', format: 'der' },
      privateKeyEncoding: { type: 'pkcs8', format: 'der' },
    });
    const res = await postJson('/api/organizations', {
      name: ORG_NAME,
      billingEmail: email,
      collectionName: encryptCipherString(orgKeyBytes, Buffer.from('ferrowarden-test-collection')),
      key: encOrgKey,
      keys: {
        publicKey: kp.publicKey.toString('base64'),
        encryptedPrivateKey: encryptCipherString(orgKeyBytes, kp.privateKey),
      },
      planType: 0,
    });
    if (res.status !== 200) {
      console.error(`[seed] creating the organisation failed (${res.status}): ${res.body}`);
      return 1;
    }
    console.log(`  created organisation: ${ORG_NAME}`);
    sync = await syncVault();
    org = findOrg(sync);
  }
  let orgKey = null;
  let collectionId = null;
  if (org) {
    orgKey = rsaUnwrap(privateKey, org.key);
    const col = (sync.collections || []).find((c) => (c.organizationId || c.OrganizationId) === org.id);
    collectionId = col ? col.id : null;
    if (orgNeeded && !collectionId) {
      console.error('[seed] the test organisation has no collection');
      return 1;
    }
  }

  // The key that encrypts an item's fields: its own key if it has one,
  // otherwise the user's (or the organisation's) key.
  // Items of any other organisation (the restricted one of bw-seed-hidden.js)
  // are not this seeder's: no key, so they are skipped.
  const baseKeyFor = (orgId) => (orgId ? (org && orgId === org.id ? orgKey : null) : symKey);
  const itemKeyOf = (c) => {
    const base = baseKeyFor(c.organizationId);
    if (!base) return null;
    return c.key ? decryptCipherString(base, c.key) : base;
  };

  // 6. List existing items for idempotency: name -> [{ id, uris }].
  const wantUri = (u) => (typeof u === 'string' ? { uri: u, match: null } : { uri: u.uri, match: u.match ?? null });
  const uriSig = (list) => list.map((u) => `${u.uri}|${u.match === undefined ? null : u.match}`);
  const existingAll = new Map();
  for (const c of sync.ciphers || []) {
    if (c.deletedDate) continue; // already in the trash
    try {
      const k = itemKeyOf(c);
      if (!k) continue;
      const name = decryptCipherString(k, c.name).toString('utf8');
      const uris = ((c.login && c.login.uris) || [])
        .filter((u) => u.uri)
        .map((u) => ({ uri: decryptCipherString(k, u.uri).toString('utf8'), match: u.match ?? null }));
      // Current clients write a checksum with every URI; bw serve ignores the
      // URIs of an item that has its own key and no checksum, so such an item
      // (an earlier version of this seeder wrote them) is rewritten below.
      const checksums = ((c.login && c.login.uris) || []).filter((u) => u.uri).every((u) => u.uriChecksum);
      if (!existingAll.has(name)) existingAll.set(name, []);
      existingAll.get(name).push({ id: c.id, uris, orgId: c.organizationId || null, stale: !!c.key && !checksums });
    } catch (_) { /* skip undecryptable items */ }
  }

  // Ferrowarden refuses ambiguous names, so the seed must leave exactly one
  // item per seeded name. Move extra copies (from earlier non-idempotent runs)
  // to the trash - only for names this seed file manages.
  const sameUris = (a, b) => {
    const x = uriSig(a), y = uriSig(b);
    return x.length === y.length && x.every((u, i) => u === y[i]);
  };
  const existing = new Map();
  let trashed = 0;
  for (const cred of credentials) {
    const copies = existingAll.get(cred.name) || [];
    if (copies.length === 0) continue;
    const want = (cred.uris || []).map(wantUri);
    const keep = copies.find((c) => sameUris(c.uris, want) && !c.stale) || copies.find((c) => sameUris(c.uris, want)) || copies[0];
    existing.set(cred.name, keep);
    for (const extra of copies.filter((c) => c !== keep)) {
      const res = await request('PUT', `/api/ciphers/${extra.id}/delete`, null, authHeaders());
      if (res.status === 200 || res.status === 204) {
        console.log(`  trashed duplicate: ${cred.name}`);
        trashed++;
      } else {
        console.error(`  ERROR trashing duplicate ${cred.name} (${res.status}): ${res.body}`);
      }
    }
  }

  // 7. Create missing credentials; update existing ones whose URIs differ.
  // Ferrowarden only sends a credential to hosts in its item's URIs, so stale
  // URIs from an older seed would break the integration tests.
  let created = 0;
  let updated = 0;
  let skipped = 0;
  let failed  = 0;

  const FIELD_TYPES = { text: 0, hidden: 1, boolean: 2, linked: 3 };
  const LINKED_IDS  = { username: 100, password: 101 };

  for (const cred of credentials) {
    const { name, value, note = '', type = 'login', username, totp, reprompt, fields = [] } = cred;
    const uris = (cred.uris || []).map(wantUri);
    const current = existing.get(name);

    if (current && sameUris(current.uris, uris) && !current.stale) {
      console.log(`  skip (exists): ${name}`);
      skipped++;
      continue;
    }

    // Which key encrypts this item: the org's or the user's, and a fresh key of
    // its own if the entry asks for one.
    const base = baseKeyFor(cred.org ? org && org.id : null);
    if (!base) { console.error(`  ERROR ${name}: no key for this item`); failed++; continue; }
    const ownKey = cred.cipher_key ? crypto.randomBytes(64) : null;
    const k = ownKey || base;
    const empties = new Set(cred.empty_string || []);
    const enc = (s, what) => {
      if (what && empties.has(what)) return encryptCipherString(k, Buffer.alloc(0));
      return (s === undefined || s === null || s === '') ? null : encryptCipherString(k, Buffer.from(String(s), 'utf8'));
    };
    const encObj = (o) => Object.fromEntries(Object.entries(o || {}).map(([p, v]) => [p, enc(v)]));

    const encFields = fields.map((f) => {
      const t = FIELD_TYPES[f.type || 'text'];
      return t === 3
        ? { type: 3, name: enc(f.name), value: null, linkedId: LINKED_IDS[f.linked] }
        : { type: t, name: enc(f.name), value: enc(f.value), linkedId: null };
    });

    const TYPES = { login: 1, secure_note: 2, card: 3, identity: 4, ssh: 5 };
    const cipher = {
      type: TYPES[type],
      name: enc(name),
      notes: enc(note),
      reprompt: reprompt ? 1 : 0,
      encryptedFor: userUuid,
      fields: encFields.length ? encFields : null,
      key: ownKey ? encryptCipherString(base, ownKey) : null,
    };
    if (cred.org) cipher.organizationId = org.id;
    if (type === 'secure_note') {
      cipher.secureNote = { type: 0 };
    } else if (type === 'card') {
      cipher.card = encObj(cred.card);
    } else if (type === 'identity') {
      cipher.identity = encObj(cred.identity);
    } else if (type === 'ssh') {
      cipher.sshKey = encObj(cred.ssh);
    } else {
      cipher.login = {
        uris: uris.length
          ? uris.map((u) => ({
              uri: enc(u.uri),
              match: u.match,
              // base64(SHA-256(uri)), encrypted like the URI: what clients write.
              uriChecksum: enc(crypto.createHash('sha256').update(u.uri, 'utf8').digest('base64')),
            }))
          : null,
        username: enc(username, 'username'),
        password: enc(value, 'password'),
        passwordRevisionDate: null,
        totp: enc(totp, 'totp'),
        autofillOnPageLoad: null,
      };
    }
    // Item types that carry no URIs still record the entry's own, for the
    // notes of a secure note with bindings (handled as a field by the caller).

    if (current) {
      const res = await putJson(`/api/ciphers/${current.id}`, cipher);
      if (res.status === 200) {
        console.log(`  updated URIs: ${name}`);
        updated++;
      } else {
        console.error(`  ERROR updating ${name} (${res.status}): ${res.body}`);
        failed++;
      }
      continue;
    }

    const createRes = cred.org
      ? await postJson('/api/ciphers/create', { cipher, collectionIds: [collectionId] })
      : await postJson('/api/ciphers', cipher);
    if (createRes.status === 200 || createRes.status === 201) {
      console.log(`  created: ${name}`);
      created++;
      if (cred.archived) {
        const id = JSON.parse(createRes.body).id;
        const arch = await request('PUT', `/api/ciphers/${id}/archive`, null, authHeaders());
        if (arch.status === 200 || arch.status === 204) {
          console.log(`  archived: ${name}`);
        } else {
          console.error(`  NOTE: this server could not archive ${name} (${arch.status})`);
        }
      }
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
