# Native backend test data (tests only, never used at runtime)

| Path | What it is |
|---|---|
| `vectors.json` | Known-answer vectors for the key hierarchy and EncStrings, generated independently by `tests/native-vectors/gen.js` (Node `crypto`). |
| `webvault/` | A throwaway account created by hand in the web vault bundled with Vaultwarden 1.37.5: the token response (key material only, no tokens) and `/api/sync` response captured verbatim, and `expected.json` with the values the Bitwarden CLI 2026.11.0 decrypted from the same account (run once by hand; no CLI is part of Ferrowarden or its CI). |
| `webvault-hidden/` | The same organisation seen by a second throwaway account whose collection has "Hide passwords" (`viewPassword: false`). |

Everything here is a dummy: the accounts, their master passwords (stored in `expected.json`, because the tests must unlock them) and every item value existed only on a disposable Vaultwarden instance that has since been deleted. The SSH key, card and identity items stay encrypted; their decrypted values are deliberately not in `expected.json`, since Ferrowarden does not serve those kinds.

To capture again: create the account and items in a web vault, then save `POST /identity/accounts/prelogin`, the password-grant token response (drop every `*token*` member) and `GET /api/sync` with `Bitwarden-Client-Version` set to a current client version, and take the reference values from the same account, by reading them in the web vault or with a one-off `bw list items` on your own machine. Recapture on each Vaultwarden minor release (docs/native-vault.md, "How formats are verified").
