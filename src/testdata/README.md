# Test fixtures (tests only — never used at runtime)

| File | What it is |
|---|---|
| `healthcheck-server.crt` / `.key` | Self-signed certificate and key for the `ferrowarden healthcheck` certificate-pinning tests. |
| `healthcheck-other.crt` | A different self-signed certificate: pinning must reject it. |
| `tls-test-ca.crt` | A throwaway test CA. **Its private key was not kept.** |
| `tls-test-server.crt` / `.key` | A server certificate for `127.0.0.1` / `localhost` (EC P-256, `CA:FALSE`, `serverAuth`) signed by `tls-test-ca.crt`. Used by the metrics-listener TLS tests with **full certificate verification** against the test CA. |
| `tls-test-other-ca.crt` | An unrelated CA (private key not kept): a client that trusts only it must refuse the server. |

Tests never disable certificate verification. To regenerate the TLS fixtures (valid for 100 years):

```sh
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout ca.key \
  -out tls-test-ca.crt -days 36500 -subj "/CN=Ferrowarden test CA (tests only)" \
  -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign,cRLSign"
openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout tls-test-server.key \
  -out server.csr -subj "/CN=localhost"
printf "basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth\nsubjectAltName=IP:127.0.0.1,DNS:localhost\n" > ext.cnf
openssl x509 -req -in server.csr -CA tls-test-ca.crt -CAkey ca.key -CAcreateserial \
  -out tls-test-server.crt -days 36500 -extfile ext.cnf
rm ca.key server.csr ext.cnf tls-test-ca.srl
# tls-test-other-ca.crt: the first command again with another CN, keeping only the .crt
```
