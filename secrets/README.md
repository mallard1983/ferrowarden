# secrets/

This directory holds Docker secret files. It is listed in `.gitignore` and must never be committed.

Create these files before running `docker compose up`:

```sh
# Your Vaultwarden API key (from Account Settings → API Key in the web UI)
echo -n "user.xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" > bw_client_id
echo -n "YourClientSecretHere"                       > bw_client_secret

# Your Vaultwarden master password
echo -n "YourMasterPasswordHere"                     > bw_master_password

# Admin key for Ferrowarden (minimum 32 characters, random)
openssl rand -base64 48 | tr -dc 'A-Za-z0-9' | head -c 48 > ferrowarden_admin_key

chmod 600 *
```

See [docs/setup.md](../docs/setup.md) for the full setup guide.
