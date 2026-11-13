# wetland

**Connect like there is no firewall. Securely.**

`wetland` lets two machines behind NAT/firewalls reach each other knowing only a
shared secret — no port forwarding, no public IP, no certificates. They meet at a
blind **relay** and then speak an end-to-end encrypted channel the relay cannot
read.

It is a ground-up reimplementation of the ideas behind
[THC's gsocket](https://github.com/hackerschoice/gsocket), written in C on top of
OpenSSL 3, with a deliberately **modern cryptographic core** and a **self-hostable
relay**.

```
   wld -s SECRET -l -i                 wld -s SECRET -i
   (behind NAT, serves a shell)        (anywhere in the world)
            │                                   │
            │   encrypted (ChaCha20-Poly1305)   │
            └──────────────┐     ┌──────────────┘
                           ▼     ▼
                   ┌───────────────────┐
                   │  wetland-relay    │  sees only: 16-byte rendezvous
                   │  (blind rendezvous)│  address + ciphertext
                   └───────────────────┘
```

> ⚠️ **Dual-use tool.** wetland is for authorized remote administration,
> penetration testing, CTFs, and connectivity research — the same space as the
> original gsocket. Only use it on systems you own or are authorized to access.

---

## Quick start

```sh
make                      # builds bin/wld and bin/wetland-relay (needs OpenSSL 3)
make test                 # unit + end-to-end tests
```

Run your own relay (one public host, any cheap VPS):

```sh
./bin/wetland-relay -p 7440 -v
```

Point both clients at it (`-H host -p port`, or the `WLD_RELAY_HOST` /
`WLD_RELAY_PORT` env vars), then:

```sh
# machine A (behind a firewall) — serve an interactive shell
wld -g -l -i
#   wld: generated secret: 7Kp9mXr... <- share this out-of-band

# machine B (anywhere) — log in
wld -s 7Kp9mXr... -i
```

More recipes:

```sh
# send a file                       # receive it
wld -s SEC < movie.mkv              wld -s SEC -l > movie.mkv

# run a command remotely, stream the result back
wld -s SEC -l -e 'journalctl -n50'   # server side
wld -s SEC                           # client side (prints the output)

# pipe anything
tar cz ./src | wld -s SEC           wld -s SEC -l | tar xzv
```

| flag | meaning |
|------|---------|
| `-s SECRET` | shared secret (both peers must match) |
| `-k FILE` | read the secret from a file |
| `-g` | generate a secret, print it, use it |
| `-l` | listen mode (default is connect) |
| `-i` | interactive PTY shell (listener serves it) |
| `-e CMD` | run `CMD`, wire its stdio to the tunnel |
| `-w` | (connect) wait for the listener to appear |
| `-R SECS` | rotate the rendezvous address every `SECS` seconds |
| `-H` / `-p` | relay host / port |
| `-v` | verbose |

---

## How it works

1. **Derivation.** Both peers run the secret through HKDF-SHA256 with
   domain-separated salts to get three independent values:
   - a 16-byte **rendezvous address** (where they meet on the relay),
   - a 32-byte **PSK** (authenticates the end-to-end handshake),
   - a 16-byte **ownership token** (protects the listen slot).
2. **Rendezvous.** The listener registers its address at the relay; the
   connector asks for the same address. The relay pairs them and splices their
   TCP streams. It learns the address, nothing else.
3. **Handshake.** Over the spliced pipe the peers run a
   [Noise-`NNpsk0`](https://noiseprotocol.org/noise.html)-style authenticated key
   exchange: ephemeral X25519 Diffie-Hellman mixed with the PSK, then explicit
   key confirmation. An eavesdropper (including the relay) can't derive the keys;
   an active man-in-the-middle without the secret fails the confirmation and both
   ends abort.
4. **Transport.** Everything after that is ChaCha20-Poly1305 records with
   per-direction 64-bit nonce counters and length-prefixed framing. Clean
   half-close is honored so pipes and `-e` commands see EOF correctly.

---

## What I changed vs. gsocket

I studied the gsocket source (its GSRN protocol, SRP/TLS layer, address
derivation and `gs-netcat` tooling) and rebuilt the concept with these
**deliberate differences**:

### 1. Modern crypto instead of TLS-SRP  *(the big one)*
gsocket negotiates end-to-end security with OpenSSL **TLS-SRP**
(`SRP-AES-256-CBC-SHA`, a 4096-bit prime, CBC mode). That family is **deprecated
and being removed from modern TLS/OpenSSL**, uses a non-AEAD CBC cipher, and the
big finite-field DH is slow.

wetland uses a **Noise-`NNpsk0`-style** exchange:
- **X25519** ephemeral DH — fast, modern, constant-time.
- **ChaCha20-Poly1305** AEAD transport — authenticated encryption, no padding
  oracles.
- **HKDF-SHA256** key schedule with a hashed transcript + **explicit key
  confirmation** for mutual authentication and MITM detection.
- **Forward secrecy** from the ephemeral keys: recording traffic and later
  learning the secret still doesn't decrypt past sessions.

### 2. A relay you can actually run
gsocket's GSRN is a closed, hosted service; the repo ships no relay. wetland
includes **`wetland-relay`** — a single-file, `poll(2)`-based, dependency-light
rendezvous server. You self-host it, so the whole system is testable end-to-end
on one box and you never depend on someone else's infrastructure.

### 3. Tracking-resistant, rotating addresses
gsocket's rendezvous address is a **static** hash of the secret, so a
relay-side observer can correlate every session that ever uses that secret.
wetland can derive the address from `HKDF(secret, time-epoch)` (`-R SECS`), so
the meeting point **rotates over time** while the secret stays the same. The
connector probes neighbouring epochs to tolerate clock skew.

### 4. Cleaner framing
gsocket multiplexes control and data in-band using a `0xFB` **escape byte**
scheme. wetland uses straightforward **length-prefixed AEAD records** and a tiny
fixed relay-control vocabulary — simpler to reason about and to audit.

### What I kept
The core insight is gsocket's and it's a good one: *stop thinking about IPs and
ports; two programs that share a secret should just be able to talk.* wetland
keeps the secret-as-address model, the listener/connector roles, the ownership
token idea, and the "netcat on steroids" ergonomics.

---

## Security notes & threat model

- **The relay is untrusted** for confidentiality and integrity. It sees the
  rendezvous address and ciphertext only. It *can* deny service (it's the meeting
  point) and, without address rotation, correlate sessions by address.
- **Secret strength matters.** The address and PSK are only as strong as the
  secret. `-g` generates ~119 bits; don't hand-pick short secrets.
- **Key confirmation** rejects a wrong secret or an active MITM before any
  application data flows.
- This is **independent, unaudited** software. The crypto is built from
  well-known primitives and a standard pattern, but it has not had a third-party
  review. Don't guard lives with it.

See [`docs/PROTOCOL.md`](docs/PROTOCOL.md) for the wire format and key schedule.

---

## Project layout

```
src/wld_crypto.{c,h}   secret derivation, Noise handshake, AEAD   (the core)
src/wld_tunnel.{c,h}   non-blocking encrypted I/O pump
src/wld_net.{c,h}      socket helpers
src/wld_proto.h        relay wire protocol + framing constants
src/relay.c            wetland-relay — the rendezvous server
src/client.c           wld — the client (pipe / exec / PTY modes)
tests/                 crypto unit tests + end-to-end shell test
```

Build needs a C11 compiler and **OpenSSL ≥ 3.0** (`libcrypto`), plus `libutil`
for `forkpty` on Linux.

---

## Roadmap

Not yet implemented (contributions welcome): SOCKS5 proxy mode, multi-connection
TCP port-forwarding, terminal window-size (`SIGWINCH`) propagation, Tor/SOCKS
egress to the relay, multi-relay load distribution, and daemon/background mode.

## License

BSD-2-Clause. See [`LICENSE`](LICENSE).
