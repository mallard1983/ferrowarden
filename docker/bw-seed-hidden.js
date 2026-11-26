#!/usr/bin/env node
/**
 * bw-seed-hidden.js
 *
 * Seeds an item whose collection hides passwords from the test account
 * (`viewPassword: false` in the account's sync): the fixture for the
 * "hidden passwords are refused by default" tests (docs/native-vault.md).
 *
 * Owners and admins always see passwords, so this needs two accounts:
 *   - the owner (HIDDEN_OWNER_EMAIL, registered by setup-entrypoint.sh) creates
 *     the organisation "ferrowarden-test-restricted-org" with a collection and
 *     the item `hidden_password_item` in it;
 *   - the test account (SETUP_EMAIL, the one Ferrowarden logs in as) is invited
 *     as an ordinary member (type 2) with access to that collection and
 *     hidePasswords = true.
 * With no SMTP configured Vaultwarden marks an invited member accepted at
 * once; the owner then confirms the member by wrapping the organisation key
 * with the member's public key.
 *
 * Idempotent. Node.js built-in modules only (bw-lib.js).
 *
 * Environment:
 *   BW_SERVER_URL          - Vaultwarden base URL
 *   SETUP_EMAIL            - the test account (the member)
 *   HIDDEN_OWNER_EMAIL     - the organisation owner
 *                            (default: org-owner@ferrowarden.test)
 *   SETUP_MASTER_PASSWORD  - master password of both accounts
 *   HIDDEN_FILE            - the item to seed (default: /seed/hidden.json, i.e.
 *                            tests/seed/hidden.json): name, value (password),
 *                            username, note, uris
 */

const crypto = require('crypto');
const fs     = require('fs');
const lib    = require('./bw-lib.js');

const serverUrl   = process.env.BW_SERVER_URL;
const memberEmail = process.env.SETUP_EMAIL;
const ownerEmail  = process.env.HIDDEN_OWNER_EMAIL || 'org-owner@ferrowarden.test';
const password    = process.env.SETUP_MASTER_PASSWORD;

const ORG_NAME        = 'ferrowarden-test-restricted-org';
const COLLECTION_NAME = 'ferrowarden-test-restricted-collection';
const hiddenFile      = process.env.HIDDEN_FILE || '/seed/hidden.json';
const CLIENT_HEADERS  = { 'Bitwarden-Client-Name': 'cli', 'Bitwarden-Client-Version': '2024.12.0' };
const MEMBER_STATUS   = { invited: 0, accepted: 1, confirmed: 2 };

if (!serverUrl || !memberEmail || !password) {
  console.error('Required env vars: BW_SERVER_URL, SETUP_EMAIL, SETUP_MASTER_PASSWORD');
  process.exit(1);
}

const client = lib.makeClient(serverUrl);
let accessToken = null;
const authHeaders = (extra = {}) => ({ Authorization: `Bearer ${accessToken}`, ...CLIENT_HEADERS, ...extra });
const getAuthed = (path) => client.request('GET', path, null, authHeaders());
const postJson = (path, obj) =>
  client.request('POST', path, JSON.stringify(obj), authHeaders({ 'Content-Type': 'application/json' }));

async function main() {
  const item = JSON.parse(fs.readFileSync(hiddenFile, 'utf8'));
  const ITEM_NAME = item.name;
  // 1. Log in as the owner.
  const login = await lib.loginWithPassword(client, ownerEmail, password, 'ferrowarden-seeder-owner');
  accessToken = login.token;
  const ownerId = JSON.parse(Buffer.from(login.token.split('.')[1], 'base64').toString()).sub;
  console.log(`[hidden] Owner ${ownerEmail}: ${lib.describeKdf(login.kdf)}`);
  const symKey = lib.decryptCipherString(login.stretchKey, login.data.Key || login.data.key);
  const encPriv = login.data.PrivateKey || login.data.privateKey;
  const privateKey = crypto.createPrivateKey({
    key: lib.decryptCipherString(symKey, encPriv), format: 'der', type: 'pkcs8' });

  const sync = async () => {
    const res = await getAuthed('/api/sync?excludeDomains=true');
    if (res.status !== 200) throw new Error(`sync failed (${res.status})`);
    return JSON.parse(res.body);
  };
  let data = await sync();
  const findOrg = (s) => (s.profile.organizations || []).find((o) => o.name === ORG_NAME);

  // 2. The restricted organisation, with its collection.
  let org = findOrg(data);
  if (!org) {
    const orgKeyBytes = crypto.randomBytes(64);
    const kp = crypto.generateKeyPairSync('rsa', {
      modulusLength: 2048,
      publicKeyEncoding: { type: 'spki', format: 'der' },
      privateKeyEncoding: { type: 'pkcs8', format: 'der' },
    });
    const res = await postJson('/api/organizations', {
      name: ORG_NAME,
      billingEmail: ownerEmail,
      collectionName: lib.encryptCipherString(orgKeyBytes, Buffer.from(COLLECTION_NAME)),
      key: lib.rsaWrap(crypto.createPublicKey(privateKey), orgKeyBytes),
      keys: {
        publicKey: kp.publicKey.toString('base64'),
        encryptedPrivateKey: lib.encryptCipherString(orgKeyBytes, kp.privateKey),
      },
      planType: 0,
    });
    if (res.status !== 200) throw new Error(`creating the organisation failed (${res.status}): ${res.body}`);
    console.log(`  created organisation: ${ORG_NAME}`);
    data = await sync();
    org = findOrg(data);
  }
  const orgKey = lib.rsaUnwrap(privateKey, org.key);
  const collection = (data.collections || []).find((c) => (c.organizationId || c.OrganizationId) === org.id);
  if (!collection) throw new Error('the restricted organisation has no collection');

  // 3. The item, in the collection.
  const exists = (data.ciphers || []).some((c) => {
    if (c.organizationId !== org.id || c.deletedDate) return false;
    try { return lib.decryptCipherString(orgKey, c.name).toString('utf8') === ITEM_NAME; } catch (_) { return false; }
  });
  if (exists) {
    console.log(`  skip (exists): ${ITEM_NAME}`);
  } else {
    const enc = (s) => lib.encryptCipherString(orgKey, Buffer.from(s, 'utf8'));
    const cipher = {
      type: 1,
      organizationId: org.id,
      name: enc(ITEM_NAME),
      notes: item.note ? enc(item.note) : null,
      reprompt: 0,
      encryptedFor: ownerId,
      fields: null,
      key: null,
      login: {
        uris: (item.uris || []).map((uri) => ({
          uri: enc(uri),
          match: null,
          uriChecksum: enc(crypto.createHash('sha256').update(uri, 'utf8').digest('base64')),
        })),
        username: item.username ? enc(item.username) : null,
        password: enc(item.value),
        passwordRevisionDate: null,
        totp: null,
        autofillOnPageLoad: null,
      },
    };
    const res = await postJson('/api/ciphers/create', { cipher, collectionIds: [collection.id] });
    if (res.status !== 200 && res.status !== 201) {
      throw new Error(`creating ${ITEM_NAME} failed (${res.status}): ${res.body}`);
    }
    console.log(`  created: ${ITEM_NAME}`);
  }

  // 4. The test account as an ordinary member whose collection hides passwords.
  const listMembers = async () => {
    const res = await getAuthed(`/api/organizations/${org.id}/users`);
    if (res.status !== 200) throw new Error(`listing members failed (${res.status}): ${res.body}`);
    const body = JSON.parse(res.body);
    return body.data || body.Data || [];
  };
  const emailOf = (m) => (m.email || m.Email || '').toLowerCase();
  let member = (await listMembers()).find((m) => emailOf(m) === memberEmail.toLowerCase());
  if (!member) {
    const res = await postJson(`/api/organizations/${org.id}/users/invite`, {
      emails: [memberEmail],
      type: 2, // User
      accessAll: false,
      collections: [{ id: collection.id, readOnly: false, hidePasswords: true, manage: false }],
      groups: [],
    });
    if (res.status !== 200) throw new Error(`inviting ${memberEmail} failed (${res.status}): ${res.body}`);
    console.log(`  invited: ${memberEmail}`);
    member = (await listMembers()).find((m) => emailOf(m) === memberEmail.toLowerCase());
    if (!member) throw new Error('the invited member is not in the member list');
  }
  if (member.status === MEMBER_STATUS.invited) {
    throw new Error('the member is still "invited" (is SMTP configured? the test stack has none)');
  }
  if (member.status === MEMBER_STATUS.accepted) {
    const userId = member.userId || member.UserId;
    const pk = await getAuthed(`/api/users/${userId}/public-key`);
    if (pk.status !== 200) throw new Error(`reading the member's public key failed (${pk.status}): ${pk.body}`);
    const pub = crypto.createPublicKey({
      key: Buffer.from(JSON.parse(pk.body).publicKey, 'base64'), format: 'der', type: 'spki' });
    const res = await postJson(`/api/organizations/${org.id}/users/${member.id}/confirm`, {
      key: lib.rsaWrap(pub, orgKey),
    });
    if (res.status !== 200) throw new Error(`confirming ${memberEmail} failed (${res.status}): ${res.body}`);
    console.log(`  confirmed: ${memberEmail}`);
  } else {
    console.log(`  skip (member confirmed): ${memberEmail}`);
  }

  console.log('\nDone. The item is in a collection that hides passwords from the test account.');
  return 0;
}

main().then((code) => process.exit(code)).catch((e) => {
  console.error('[hidden] Fatal error:', e.message);
  process.exit(1);
});
