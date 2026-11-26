# certs/

Place your TLS certificate and private key here before starting Ferrowarden with `tls_enabled = true`.

This directory is listed in `.gitignore` — only this README is tracked. **Never commit certificate files or private keys.**

These files are for the **agent-facing** TLS listener only. The internal CA and Vaultwarden certificate used between Ferrowarden and Vaultwarden are generated automatically into the `internal-pki` Docker volume by the `internal-certs` service (`ferrowarden internal-certs`, see [docs/tls.md](../docs/tls.md#the-internal-ca-how-it-is-made)) — nothing to place here.

---

## Quick start (dev / homelab)

The setup scripts generate a self-signed certificate automatically:

```sh
# Linux/Mac:
./scripts/dev-setup.sh

# Windows (PowerShell):
.\scripts\dev-setup.ps1
```

For manual generation or a production CA-signed certificate, see **[docs/tls.md](../docs/tls.md)**.

---

## Files that belong here

| File | Description |
|---|---|
| `server.crt` | Server certificate (PEM). Mounted read-only into the container. |
| `server.key` | Server private key (PEM). Mounted read-only into the container. Keep `chmod 400`. |
| `ca.crt` | *(Optional)* Your local CA certificate. Copy this to connecting machines to trust the cert. |
| `ca.key` | *(Optional)* Your local CA private key. Keep this secret — anyone who has it can issue trusted certs. |

---

## Certificate rotation

Ferrowarden does not reload certificates live. After replacing the files:

```sh
docker compose restart ferrowarden
```
