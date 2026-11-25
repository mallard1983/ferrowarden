<img src="../branding/assets/png/banners/ferrowarden-docs-header.png" width="100%" alt="">

# Deployment Profiles

How much isolation you put around Ferrowarden is your decision, and it should match what the vault protects. This page describes two profiles, what each one defends against, and what it does not. The profiles add up: *Hardened* is *Standard* plus a dedicated machine.

| | Standard | Hardened |
|---|---|---|
| What it is | The shipped `docker-compose.yml`, as is | The same stack on a dedicated VM, optionally under gVisor, with outbound firewall rules |
| Effort | None beyond [setup](setup.md) | A VM, a firewall policy, optionally a different container runtime |
| Kernel | Shared with the host and everything else on it | The VM's own; nothing else runs on it |
| Defends against | A bug in Ferrowarden or `bw serve` that gives an attacker code execution inside a container | The same, plus a container escape reaching other workloads, plus data leaving to destinations you did not intend |
| Does not defend against | A kernel or runtime vulnerability that escapes the container; a compromise of the Docker host | A compromise of the hypervisor; a compromised Ferrowarden using the hosts you allowed it to reach |

Neither profile makes a compromised Ferrowarden harmless. Ferrowarden has to decrypt a credential to use it, so an attacker who controls the process can use whatever it can reach. The profiles limit what that attacker can *do next* and how far they can get. [Security Model](security.md) states the threat model and the limits.

---

## Standard: the hardened Compose file

`docker-compose.yml` ships hardened. Nothing needs to be switched on.

### What the `ferrowarden` container has

- **A static binary on `scratch`.** The image holds the `ferrowarden` binary (statically linked against musl), a two-line `/etc/passwd` and `/etc/group` for the fixed UID/GID 999, and an empty `/data` owned by that user. There is no shell, no package manager, no `curl`, no libc and no CA bundle (TLS roots are compiled into the binary; an operator CA is a mounted file named in the settings). An attacker who gets code running in the process cannot start a shell, because there is none, and cannot download tools with `curl` or `apt`. The image is about 23 MB, down from about 165 MB on Debian.
- **Secrets read by the binary.** `FERROWARDEN_ADMIN_KEY_FILE` and the notifier `*_TOKEN_FILE` variables name files; Ferrowarden reads them itself into memory that is wiped on drop. No entrypoint script exports the admin key, so it is not in the process environment (`/proc/<pid>/environ` holds only the path of the file, and so does `docker inspect`). CI checks this on every run.
- **`read_only: true`.** The root filesystem cannot be written. Every path Ferrowarden writes at run time is on a volume (see the table below), so no `tmpfs` is needed. An attacker cannot replace the binary or drop files in the image.
- **`cap_drop: [ALL]`.** No Linux capabilities. Port 3000 is unprivileged, so none is needed.
- **`no-new-privileges`.** The process cannot gain privileges through setuid binaries or file capabilities. There are none in the image, but the flag also holds if one is ever added.
- **`pids_limit: 256` and `mem_limit: 1g`.** A runaway or abused process cannot exhaust the host. Raise the memory limit only if your vault is very large or your Vaultwarden account uses an Argon2 memory setting above the default (the admin UI's sign-in derives a key with it; 64 MiB by default, up to 1 GiB).
- **`USER 999:999`.** Never root.
- **No Docker socket,** and no capability to ask for one.
- **A health check that is the binary itself.** `ferrowarden healthcheck` requests `GET /health` on the server's own port, over TLS when TLS is on, and exits 0 only on HTTP 200 within 3 seconds. It reads the same settings as the server and needs no secrets. With TLS on it **verifies** the server's certificate: it accepts only the certificate in `tls_cert_file` (the one the server was configured with) and checks that the peer can sign with its key. The check addresses the server as `127.0.0.1`, which a certificate for `agents.example.com` does not name, so the name cannot be what is verified; pinning to the configured certificate is what replaces it. Verification is never switched off, so a self-signed certificate needs no special flag, and a different certificate on the port fails the check. It does not judge expiry (a lapsed certificate is for your clients to report, and failing the container would only restart it).

### Writable paths

| Path in the container | Written by | How it is mounted |
|---|---|---|
| `/data/agent_keys.json` and `/data/agent_keys.tmp` | The agent key store: written to the `.tmp` sibling, then renamed over the file, so both must be in the same writable directory | The `ferrowarden-keys` named volume at `/data` |
| `/data/events/events.jsonl` and its rotated copies | The event file sink, **only if you enable it** (`FERROWARDEN_EVENTS__FILE`) | The same volume: use a path under `/data` |
| Nothing else | | There is no `tmpfs` and no writable layer in use |

If you point `FERROWARDEN_EVENTS__FILE` somewhere else, mount a volume there that UID 999 can write. A path in the image, such as `/tmp/...`, fails at startup under `read_only: true`.

### What the `bw-serve` container has

`bw serve` is the largest attack surface in the stack: Node.js and the Bitwarden CLI's npm dependency tree, holding the decrypted vault while unlocked. It is on an internal-only network, and it gets the same restrictions as Ferrowarden:

- `read_only: true`, `cap_drop: [ALL]`, `no-new-privileges`, `pids_limit: 128`, `mem_limit: 1g`.
- Its one writable path is the CLI's data directory, `/home/node/.config/Bitwarden CLI` (a single `data.json`: the login state and the encrypted local vault cache). Production keeps that on the `bw-data` volume so the CLI keeps its device identity across restarts; the test stack uses a `tmpfs` there, because it logs in again with the API key on every start, which the entrypoint handles.

**Be clear about the limit:** the `bw-serve` image is a stock Node image. It still has a shell, `curl` and the rest of a Debian userland, because its entrypoint is a shell script and its health check uses `curl`. The restrictions above are what contain it, not the absence of tools. The Vaultwarden container is a third-party image that binds port 443 as root; it gets `no-new-privileges` and nothing more.

### What Standard protects against, and what it does not

It protects against the common outcomes of a bug in Ferrowarden or `bw serve`: no shell to run, no tools to fetch, no way to persist (read-only filesystem), no privileged operations (no capabilities, no privilege escalation), no fork bombs or memory exhaustion. It also means the admin key is not exposed through the environment to anything that can read `/proc/<pid>/environ` or `docker inspect`.

It does **not** protect against an escape from the container. A container shares the host's kernel: a kernel or container-runtime vulnerability reachable from inside the container is a vulnerability of the whole host. Docker's default seccomp profile narrows the kernel surface, but it is a filter on one shared kernel. A process that already holds the admin key and the vault in memory also does not need a shell to misuse them: it can call any service Ferrowarden can reach.

### Verify it

```sh
# Flags on the running containers.
docker inspect -f '{{.HostConfig.ReadonlyRootfs}} {{.HostConfig.CapDrop}} {{.HostConfig.SecurityOpt}}' \
  $(docker compose ps -q ferrowarden bw-serve)
# true [ALL] [no-new-privileges:true]   (once per container)

# The image has no shell.
docker run --rm --entrypoint /bin/sh "$(docker compose images -q ferrowarden)" -c true
# fails: no such file

# The admin key is a path, not a value, in the container configuration.
docker inspect -f '{{range .Config.Env}}{{println .}}{{end}}' $(docker compose ps -q ferrowarden) \
  | grep ADMIN_KEY
# FERROWARDEN_ADMIN_KEY_FILE=/run/secrets/ferrowarden_admin_key

# Health, as Docker sees it.
docker compose ps
docker compose exec ferrowarden /app/ferrowarden healthcheck   # exit status 0
```

On a Linux host you can also confirm the process environment itself (root only):

```sh
sudo cat /proc/$(docker inspect -f '{{.State.Pid}}' $(docker compose ps -q ferrowarden))/environ | tr '\0' '\n' | grep ADMIN_KEY
# FERROWARDEN_ADMIN_KEY_FILE=/run/secrets/ferrowarden_admin_key
```

CI runs this check, the no-shell check and a check that the image holds only the expected files, against the same `docker-compose.test.yml` that the integration suite uses.

---

## Hardened: a dedicated VM, optionally gVisor

Use this when a compromise of the Docker host would be costly: the vault holds production credentials, or the host runs other workloads you do not want in reach of a container escape.

### A VM that runs only this stack

Run the stack on its own virtual machine (Proxmox, KVM/libvirt, or any hypervisor), with nothing else on it: no other containers, no other services, no shared accounts. The VM has its own kernel, so a container escape lands in a machine that holds the same secrets as the container it escaped from and nothing more. That is the real difference from the Standard profile: the isolation boundary is the hypervisor, not a kernel feature of a shared host.

Practical points:

- A minimal, regularly patched Linux guest (Debian or similar) with automatic security updates. Only the ports you publish are reachable: the Ferrowarden port, and the Vaultwarden web vault if you use it (see `VAULTWARDEN_PUBLISH` and `FERROWARDEN_PUBLISH` in `.env.example`).
- SSH to the VM by key only, from your management network only.
- Treat the VM's disk like the vault: it holds the secret files, the `internal-pki` volume (the internal CA key) and the Vaultwarden data. Use full-disk encryption on the VM or the datastore, and back the volumes up as described in [setup](setup.md).
- Keep the hypervisor's own management interface off the networks agents and Ferrowarden can reach.

### Optional: gVisor

[gVisor](https://gvisor.dev) runs containers on a user-space kernel (`runsc`): the container's system calls are handled by gVisor instead of reaching the host kernel directly, which shrinks the kernel attack surface a container escape would have to go through. It costs some performance and compatibility, and **this project does not test gVisor in CI**: try it on a copy of your stack first.

1. Install `runsc` and register it with Docker by following gVisor's installation guide (`runsc install` adds the runtime to `/etc/docker/daemon.json`), then restart Docker.
2. Select it per service in a Compose override, `docker-compose.gvisor.yml`:

   ```yaml
   services:
     ferrowarden:
       runtime: runsc
     bw-serve:
       runtime: runsc
   ```

   ```sh
   docker compose -f docker-compose.yml -f docker-compose.gvisor.yml up -d
   ```

   Vaultwarden is a separate decision; run it under `runsc` too if it works for you.
3. Verify the runtime is in use:

   ```sh
   docker inspect -f '{{.HostConfig.Runtime}}' $(docker compose ps -q ferrowarden bw-serve)
   # runsc   (once per container)

   # A process inside a gVisor sandbox sees gVisor's kernel, not the host's.
   docker run --rm --runtime=runsc busybox dmesg | head -3
   # [    0.000000] Starting gVisor...
   ```

All the Standard restrictions still apply under gVisor; it is an additional layer, not a replacement. It does not change what a compromised Ferrowarden can reach over the network, which is what the next section addresses.

### Outbound firewall rules

Ferrowarden must make outbound connections, so a compromised process can too. Restrict where it can connect to, on the VM, outside the container's control.

What should be able to leave the VM:

| Source | Needs to reach | Everything else |
|---|---|---|
| `ferrowarden` (the `agent-facing` network) | DNS; the hosts of the APIs your agents call (the `allowed_targets` and the credentials' URIs); your push notifier and SIEM syslog endpoint if configured | Drop and log |
| `bw-serve` and `ferrowarden` (`vault-internal`) | Each other and `vaultwarden`. This network is `internal: true`: Docker gives it no route out | Already isolated |
| `vaultwarden` (the `vault-web` bridge) | Nothing for normal operation. Outbound is only needed for optional features (icon fetching, push relay, SMTP); turn those off in Vaultwarden or allow only their hosts | Drop |
| The VM itself | OS updates, NTP, your backup target | Drop |

Docker programs the firewall itself, so rules for container traffic belong in the `DOCKER-USER` chain, which Docker evaluates first and never rewrites. An outline to adapt (replace the subnet and addresses; list them with `docker network inspect <project>_agent-facing`):

```sh
AGENT_NET=172.20.0.0/16        # the agent-facing network's subnet

# Allow replies and DNS, then only the destinations you name, then drop.
iptables -I DOCKER-USER -s $AGENT_NET -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
iptables -A DOCKER-USER -s $AGENT_NET -p udp --dport 53 -d <your-resolver> -j ACCEPT
iptables -A DOCKER-USER -s $AGENT_NET -d <target-api-1> -p tcp --dport 443 -j ACCEPT
iptables -A DOCKER-USER -s $AGENT_NET -d <target-api-2> -p tcp --dport 443 -j ACCEPT
iptables -A DOCKER-USER -s $AGENT_NET -j LOG --log-prefix "fw-egress-drop: "
iptables -A DOCKER-USER -s $AGENT_NET -j DROP
```

These rules are an outline, not a tested rule set: persist them with your distribution's tooling, and test that the legitimate calls still work. Two things make them more useful than they look. Ferrowarden's own target policy (`allowed_targets`, [SSRF protection](security.md)) already refuses private and internal targets unless you list them, so the firewall is the second layer that holds when that layer has a bug. And a log of dropped connections from `ferrowarden` is a strong signal: it should never try to reach a host you did not expect.

### What Hardened protects against, and what it does not

It protects against a container escape reaching anything beyond this stack, and against a compromised process sending data to a destination you did not allow. It does **not** protect against a compromised hypervisor, against someone who can read the VM's disk (hence encryption), or against a compromised Ferrowarden using the destinations you have allowed it to reach: if an agent may call an API, a hijacked Ferrowarden may too.

---

## Choosing

- **Homelab, low-value credentials, nothing else exposed:** Standard is a sound baseline and needs nothing from you.
- **Credentials that matter, or a shared Docker host:** put the stack on its own VM and add the outbound rules.
- **Credentials that matter and a threat model that includes container escapes:** Hardened with gVisor, after testing it on your hardware.

Whichever you choose, the rest of the [deployment checklist](security.md#deployment-security-checklist) still applies.
