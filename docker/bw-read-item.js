#!/usr/bin/env node
/**
 * bw-read-item.js
 *
 * The independent reader of the credential-create and rotation tests
 * (docs/native-vault.md, "How the write path is verified"). It logs in to
 * Vaultwarden as the test account with the master password, finds the item
 * named ITEM_NAME in /api/sync, decrypts it with Node's `crypto` (bw-lib.js: no
 * Ferrowarden code, no Rust), and prints ONE line of JSON:
 *
 *   {
 *     "found": true, "count": 1,
 *     "passwordMatches": true,      // equals the value given on stdin; never printed
 *     "passwordLength": 32,
 *     "username": "admin",
 *     "uris": ["https://..."],
 *     "checksumsValid": true,       // every uriChecksum is base64(SHA-256(uri))
 *     "fieldNames": ["ferrowarden_created_by", ...],
 *     "createdBy": "<value of ferrowarden_created_by>",
 *     "approvalField": "required" | null,
 *     "organizationId": "...", "collections": ["Ferrowarden managed"],
 *     "type": 1, "hasItemKey": true, "totp": null, "notes": null,
 *     // The rotation tests (docs/managed-credentials.md):
 *     "hasNextField": false,        // the reserved ferrowarden_next field is there
 *     "nextMatches": false,         // its value equals the third line of stdin
 *     "passwordHistoryCount": 1,
 *     "historyFirstMatches": true,  // the newest history entry equals the second line of stdin
 *     "passwordRevisionDate": "2026-11-26T12:30:00.000Z" | null,
 *     "revisionDate": "..."         // the item's revision, to see that it moved
 *   }
 *
 * No password is ever printed. The test writes the values it expects to stdin
 * (one per line: the password, the previous password, the pending value), and
 * the reader says only whether the stored ones are the same (a constant-time
 * comparison). Test fixtures only: this logs in with the master password of the
 * throwaway test account.
 *
 * Editor mode: when EDIT_NOTES, EDIT_PASSWORD and/or EDIT_PENDING is set, the reader also plays "a person who
 * edits the item in the vault": it reads the item as the server holds it, sets
 * its notes to that text (encrypted with the item's key) and saves it with a
 * correct PUT (the revision it read as lastKnownRevisionDate), then prints its
 * line (with "edited": true; "notes" then shows the new text). The conflict
 * test of a rotation uses it.
 *
 * Environment:
 *   BW_SERVER_URL          Vaultwarden base URL
 *   SETUP_EMAIL            the test account
 *   SETUP_MASTER_PASSWORD  its master password (or SETUP_MASTER_PASSWORD_FILE: a file with it)
 *   ITEM_NAME              the item to read (exact name)
 *   EDIT_NOTES             (optional) set the item's notes to this text first
 *   EDIT_PASSWORD          (optional) set the item's password to this text first
 *   EDIT_PENDING           (optional) set the value of the item's pending `ferrowarden_next`
 *                          field to this text first (a person replacing the pending value)
 * stdin: line 1 the expected password (may be empty: passwordMatches is then
 *        false); line 2 the expected previous password; line 3 the expected
 *        pending value
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
const editNotes = process.env.EDIT_NOTES;
const editPassword = process.env.EDIT_PASSWORD;
const editPending = process.env.EDIT_PENDING;
// What the test expects, from stdin (never printed).
let expected = '';
let expectedPrevious = '';
let expectedNext = '';
try {
  const lines = fs.readFileSync(0, 'utf8').split('\n');
  expected = lines[0] || '';
  expectedPrevious = lines[1] || '';
  expectedNext = lines[2] || '';
} catch (_) { /* nothing on stdin */ }

/** Constant-time equality of two strings, without printing or hashing them. */
function sameText(a, b) {
  if (a === null || a === undefined) return false;
  const x = Buffer.from(a, 'utf8');
  const y = Buffer.from(b, 'utf8');
  return x.length === y.length && x.length > 0 && crypto.timingSafeEqual(x, y);
}
const CLIENT_HEADERS = { 'Bitwarden-Client-Name': 'cli', 'Bitwarden-Client-Version': '2024.12.0' };

if (!serverUrl || !email || !password || !itemName) {
  console.error('Required env vars: BW_SERVER_URL, SETUP_EMAIL, SETUP_MASTER_PASSWORD(_FILE), ITEM_NAME');
  process.exit(2);
}

const { request } = lib.makeClient(serverUrl);
const dec = (key, s) => (s ? lib.decryptCipherString(key, s).toString('utf8') : null);
const JSON_HEADERS = { 'Content-Type': 'application/json' };

// The members of an item's JSON that are the server's own: not sent back.
const RESPONSE_ONLY = [
  'object', 'id', 'creationDate', 'revisionDate', 'deletedDate', 'archivedDate',
  'attachments', 'collectionIds', 'edit', 'viewPassword', 'permissions',
  'organizationUseTotp', 'data',
];

/**
 * Save the item with new notes, as a person editing it in a client would:
 * read it as the server holds it now, change the notes, send it back with the
 * revision that was read as lastKnownRevisionDate.
 */
async function editItem(token, id, key, text, newPassword, newPending, userId) {
  const auth = { Authorization: `Bearer ${token}`, ...CLIENT_HEADERS };
  const got = await request('GET', `/api/ciphers/${id}`, null, auth);
  if (got.status !== 200) throw new Error(`could not read the item to edit it (${got.status})`);
  const item = JSON.parse(got.body);
  const body = { ...item };
  for (const m of RESPONSE_ONLY) delete body[m];
  if (text !== undefined) {
    body.notes = lib.encryptCipherString(key, Buffer.from(text, 'utf8'));
  }
  if (newPassword !== undefined) {
    // What a person changing the password in a client does to the stored item.
    body.login = { ...body.login, password: lib.encryptCipherString(key, Buffer.from(newPassword, 'utf8')) };
  }
  if (newPending !== undefined) {
    // A person replacing the value of the pending field, whatever its name's case.
    body.fields = (body.fields || []).map((f) =>
      (dec(key, f.name) || '').trim().toLowerCase() === 'ferrowarden_next'
        ? { ...f, value: lib.encryptCipherString(key, Buffer.from(newPending, 'utf8')) }
        : f);
  }
  // Vaultwarden 1.37 refuses a PUT without it (clients send their own id).
  body.encryptedFor = userId;
  body.lastKnownRevisionDate = item.revisionDate;
  const put = await request('PUT', `/api/ciphers/${id}`, JSON.stringify(body), { ...auth, ...JSON_HEADERS });
  if (put.status !== 200) throw new Error(`could not save the edit (${put.status})`);
}

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

    let edited = false;
    let current = c;
    if (editNotes !== undefined || editPassword !== undefined || editPending !== undefined) {
      await editItem(token, c.id, key, editNotes, editPassword, editPending, sync.profile.id);
      edited = true;
      // Read the item again: the line below shows what is stored now.
      const again = await request('GET', `/api/ciphers/${c.id}`, null,
        { Authorization: `Bearer ${token}`, ...CLIENT_HEADERS });
      if (again.status !== 200) throw new Error(`could not read the item again (${again.status})`);
      current = JSON.parse(again.body);
    }

    const l = current.login || {};
    const password_ = dec(key, l.password);
    const uris = (l.uris || []).filter((u) => u.uri).map((u) => ({
      uri: dec(key, u.uri),
      checksum: u.uriChecksum ? dec(key, u.uriChecksum) : null,
    }));
    const fields = (current.fields || []).map((f) => ({ name: dec(key, f.name), value: dec(key, f.value) }));
    const field = (n) => (fields.find((f) => f.name === n) || {}).value ?? null;
    const history = (current.passwordHistory || []).map((h) => dec(key, h.password));
    found.push({
      passwordMatches: sameText(password_, expected),
      passwordLength: password_ === null ? null : [...password_].length,
      username: dec(key, l.username),
      uris: uris.map((u) => u.uri),
      checksumsValid: uris.length > 0 && uris.every((u) =>
        u.checksum === crypto.createHash('sha256').update(u.uri, 'utf8').digest('base64')),
      fieldNames: fields.map((f) => f.name),
      createdBy: field('ferrowarden_created_by'),
      approvalField: field('ferrowarden_approval'),
      organizationId: current.organizationId || null,
      collections: (current.collectionIds || []).map((id) => collectionNames.get(id) || id),
      type: current.type,
      hasItemKey: !!current.key,
      totp: dec(key, l.totp),
      notes: dec(key, current.notes),
      hasNextField: fields.some((f) => f.name === 'ferrowarden_next'),
      hasRotationField: fields.some((f) => f.name === 'ferrowarden_rotation'),
      nextMatches: sameText(field('ferrowarden_next'), expectedNext),
      passwordHistoryCount: history.length,
      historyFirstMatches: history.length > 0 && sameText(history[0], expectedPrevious),
      passwordRevisionDate: l.passwordRevisionDate || null,
      revisionDate: current.revisionDate || null,
      edited,
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
