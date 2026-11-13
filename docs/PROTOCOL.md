# wetland protocol (v1)

All integers are big-endian. Primitives: X25519, XChaCha20-Poly1305 (24-byte
nonce, 16-byte tag), BLAKE2b, and a keyed-BLAKE2b PRF used as the KDF. Everything
is provided by the vendored, public-domain Monocypher — no external dependency.

The KDF is `kdf(key, msg) = BLAKE2b-keyed(key, msg)`.

## 1. Key derivation

From the user secret `S` (a UTF-8 string):

```
PSK   = kdf(key="wetland/psk/v1",   msg=S)                 [32 bytes]
ADDR  = kdf(key="wetland/addr/v1",  msg=epoch_be64 || S)   [16 bytes]
TOKEN = kdf(key="wetland/token/v1", msg=S)                 [16 bytes]
```

`epoch = 0` gives a static address. With `-R SECS`, `epoch = unixtime / SECS`,
and the connector also probes `epoch±1` to tolerate clock skew.

## 2. Relay rendezvous layer (cleartext metadata)

Client → relay **hello** (48 bytes, sent once on connect):

| off | size | field |
|-----|------|-------|
| 0 | 3 | magic `"WLD"` |
| 3 | 1 | version (`1`) |
| 4 | 1 | role: `1`=LISTEN, `2`=CONNECT |
| 5 | 1 | flags: `0x01`=WAIT |
| 6 | 2 | reserved |
| 8 | 16 | ADDR |
| 24 | 16 | TOKEN |
| 40 | 8 | reserved |

Relay → client control bytes:

| byte | name | meaning |
|------|------|---------|
| `0x10` | WAIT | registered, waiting for a peer |
| `0x11` | START | peer matched — the raw tunnel begins immediately after this byte |
| `0x12` | ERR | followed by 1 error-code byte, then close |
| `0x13`/`0x14` | PING/PONG | keepalive (pre-START) |

Error codes: `1` in-use, `2` no-server, `3` bad-token, `4` protocol, `5` busy.

Pairing: the relay matches a CONNECT to a waiting LISTEN with the same ADDR,
sends `START` to both, and from then on splices the two TCP streams verbatim.
A second LISTEN on a live ADDR is rejected (`in-use`). A CONNECT with no listener
either waits (if the WAIT flag is set) or gets `no-server`.

## 3. End-to-end handshake (after START)

The **connector is the initiator**, the **listener is the responder**. Over the
spliced pipe:

```
initiator → responder:  e_pub_i      (32)   ephemeral X25519 public key
responder → initiator:  e_pub_r      (32)
initiator → responder:  confirm_i    (16)   AEAD tag
responder → initiator:  confirm_r    (16)
```

Key schedule:

```
dh   = X25519(e_priv_self, e_pub_peer)
h    = BLAKE2b("wetland-handshake-v1" || e_pub_i || e_pub_r)
prk  = kdf(key = h, msg = dh || PSK)

k_i2r  = kdf(prk, "wld-data-i2r")   # initiator → responder data
k_r2i  = kdf(prk, "wld-data-r2i")   # responder → initiator data
kc_i2r = kdf(prk, "wld-conf-i2r")   # confirmation keys
kc_r2i = kdf(prk, "wld-conf-r2i")
```

`confirm_X = AEAD_seal(key=kc_<dir>, nonce=0, aad=h, plaintext="")` — i.e. the
16-byte tag over the transcript. Each side verifies the other's confirmation; a
failure means a wrong secret or an active MITM, and the connection is aborted.

Security: mixing `PSK` into `prk` means an attacker without the secret derives
different keys and cannot forge a confirmation (mutual authentication). The
ephemeral DH provides forward secrecy. The relay sees only the two ephemeral
public keys and ciphertext.

## 4. Transport (after confirmation)

Each record:

```
[ u16 clen ][ ciphertext : clen bytes ]        clen = plaintext_len + 16
```

- `ciphertext = AEAD_seal(key=k_<dir>, nonce=counter, aad=clen_be16, plaintext)`
- `nonce` = 24 bytes, big-endian 64-bit `counter` in the low 8 bytes, per
  direction, starting at 0 and incrementing by 1 each record. The connection is
  torn down before the counter can wrap.
- Transport keys are distinct from confirmation keys, so transport counters start
  cleanly at 0.
- Max plaintext per record: 16384 bytes. A zero-length record is a keepalive.
- TCP half-close (FIN) propagates EOF end-to-end so piped programs terminate
  correctly.
