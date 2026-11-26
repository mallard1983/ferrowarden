# Test fixtures for `ferrowarden internal-certs` (tests only, never used at runtime)

These five files are a complete `internal-pki` volume made by the **old openssl script**
(`docker/gen-internal-certs.sh` as of 0.1.x, run in an `alpine` container with OpenSSL 3.5.9,
`VW_HOSTNAME=vaultwarden`, `VW_EXTRA_SANS=localhost,127.0.0.1`). They exist to prove that
`internal-certs` reuses a CA an earlier release made, does not re-issue a valid certificate,
and signs new certificates that verify against that old `ca.crt`.

| File | What it is |
|---|---|
| `ca.crt`, `ca.key` | The internal CA (ECDSA P-256, `CN=ferrowarden-internal-ca`, 10 years from 2026-11-26). |
| `vaultwarden.crt`, `vaultwarden.key` | A server certificate signed by that CA (825 days from 2026-11-26). |
| `vaultwarden.sans` | `DNS:vaultwarden,DNS:localhost,IP:127.0.0.1` |

**The keys are throwaway test keys.** They protect nothing and exist only here. Never use
them anywhere else.

The tests set the clock explicitly (the day the fixture was made, or later), so they do not
depend on today's date. To regenerate the fixture (for example when the 825-day certificate
is no longer the interesting case), run the script from a 0.1.x checkout:

```sh
git show main~N:docker/gen-internal-certs.sh > gen.sh   # a revision that still has the script
docker run --rm -v "$PWD:/work" -e PKI_DIR=/work/pki -e CA_PUBLIC_DIR=/work/pub \
  -e VW_EXTRA_SANS=localhost,127.0.0.1 alpine sh -c 'apk add -q openssl && sh /work/gen.sh'
```

then copy `ca.crt`, `ca.key`, `vaultwarden.crt`, `vaultwarden.key` and `vaultwarden.sans`
here and update `fixture_now()` in `../tests.rs` to a time shortly after the new issue date.
