#!/usr/bin/env node
/**
 * bw-apikey.js
 *
 * Logs in to the test account with its master password and creates its
 * personal API key (client_id + client_secret), which the native vault
 * backend and the seeder use. Node.js built-in modules only.
 *
 * The KDF (PBKDF2 or Argon2id) is read from prelogin: it is whatever the
 * account was registered with (bw-register.js, TEST_KDF), never assumed.
 *
 * API response format changed in Vaultwarden 2026.x:
 *   Old: {"clientId": "user.<uuid>", "clientSecret": "..."}
 *   New: {"apiKey": "<secret>", "object": "apiKey"}
 * In the new format the client id is "user.<sub>" with <sub> the user UUID
 * from the access token.
 *
 * Environment: BW_SERVER_URL, SETUP_EMAIL, SETUP_MASTER_PASSWORD, SECRETS_DIR
 * (default /secrets). Writes bw_client_id and bw_client_secret there. Prints
 * the client id (a user UUID), never the secret.
 */

const fs   = require('fs');
const path = require('path');
const lib  = require('./bw-lib.js');

const serverUrl  = process.env.BW_SERVER_URL;
const email      = process.env.SETUP_EMAIL;
const password   = process.env.SETUP_MASTER_PASSWORD;
const secretsDir = process.env.SECRETS_DIR || '/secrets';

if (!serverUrl || !email || !password) {
  console.error('Required env vars: BW_SERVER_URL, SETUP_EMAIL, SETUP_MASTER_PASSWORD');
  process.exit(1);
}

async function main() {
  const client = lib.makeClient(serverUrl);

  const login = await lib.loginWithPassword(client, email, password, 'ferrowarden-setup');
  console.log(`[apikey] Account KDF: ${lib.describeKdf(login.kdf)}`);
  console.log('[apikey] Access token obtained.');

  // Creating the key needs the master password hash as well as the token, to
  // confirm operator intent.
  const res = await client.request('POST', '/api/accounts/api-key',
    JSON.stringify({ masterPasswordHash: login.hash }),
    { Authorization: `Bearer ${login.token}`, 'Content-Type': 'application/json' });
  if (res.status !== 200) {
    console.error(`[apikey] creating the API key failed (HTTP ${res.status})`);
    return 1;
  }
  const data = JSON.parse(res.body);
  const sub = JSON.parse(Buffer.from(login.token.split('.')[1], 'base64').toString()).sub;
  const clientId = data.clientId || data.ClientId || `user.${sub}`;
  const clientSecret = data.clientSecret || data.ClientSecret || data.apiKey || data.ApiKey;
  if (!clientId || !clientSecret) {
    console.error('[apikey] the response held no API key');
    return 1;
  }

  fs.mkdirSync(secretsDir, { recursive: true });
  // Default file mode (umask): scripts/dev-setup.* make the files readable to
  // the other test containers (ferrowarden), which run as other UIDs.
  fs.writeFileSync(path.join(secretsDir, 'bw_client_id'), clientId);
  fs.writeFileSync(path.join(secretsDir, 'bw_client_secret'), clientSecret);
  console.log('[apikey] API key created');
  console.log('[apikey] Wrote bw_client_id and bw_client_secret to the secrets directory');
  return 0;
}

main().then((code) => process.exit(code)).catch((e) => {
  console.error('[apikey] Fatal error:', e.message);
  process.exit(1);
});
