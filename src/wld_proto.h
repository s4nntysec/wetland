/*
 * wetland — wire protocol (client <-> relay rendezvous layer)
 *
 * This layer is cleartext metadata: the relay must see the 16-byte rendezvous
 * address to pair two peers. It never sees the secret, the PSK or any payload.
 * Everything after a START message is the opaque E2E tunnel (ChaCha20-Poly1305).
 *
 * All multi-byte integers are big-endian.
 */
#ifndef WLD_PROTO_H
#define WLD_PROTO_H 1

#include <stdint.h>
#include "wld_crypto.h"

#define WLD_MAGIC0 'W'
#define WLD_MAGIC1 'L'
#define WLD_MAGIC2 'D'
#define WLD_PROTO_VERSION 1

#define WLD_RELAY_DEFAULT_PORT "7440"

/* Client -> relay roles (the `role` field of the hello). */
enum {
	WLD_ROLE_LISTEN  = 1,  /* register an address and wait for a peer */
	WLD_ROLE_CONNECT = 2,  /* connect to a registered address        */
};

/* hello flags */
enum {
	WLD_HF_WAIT = 0x01,    /* connector: wait if no listener yet (-w) */
};

/*
 * Fixed 48-byte hello, sent once by the client immediately after TCP connect.
 *   magic[3] "WLD", version, role, flags, reserved[1],
 *   addr[16], token[16], reserved2[8]
 */
#define WLD_HELLO_LEN 48
struct wld_hello {
	uint8_t magic[3];
	uint8_t version;
	uint8_t role;
	uint8_t flags;
	uint8_t reserved[2];
	uint8_t addr[WLD_ADDR_LEN];
	uint8_t token[WLD_TOKEN_LEN];
	uint8_t reserved2[8];
};

/*
 * Relay -> client control messages. Each is a single byte, optionally followed
 * by a one-byte argument (for ERR). After START the stream is raw tunnel bytes.
 */
enum {
	WLD_R_WAIT  = 0x10,  /* registered / waiting for peer         */
	WLD_R_START = 0x11,  /* peer matched — tunnel begins now       */
	WLD_R_ERR   = 0x12,  /* followed by 1 error-code byte; closing */
	WLD_R_PING  = 0x13,  /* keepalive (either direction, pre-START)*/
	WLD_R_PONG  = 0x14,
};

/* Error codes carried by WLD_R_ERR. */
enum {
	WLD_E_INUSE    = 1,  /* address already has a listener          */
	WLD_E_NOSRV    = 2,  /* no listener for this address            */
	WLD_E_BADTOKEN = 3,  /* listen token mismatch on reclaim        */
	WLD_E_PROTO    = 4,  /* malformed hello / protocol violation    */
	WLD_E_BUSY     = 5,  /* relay at capacity                       */
};

/*
 * Transport framing (post-START, end-to-end):
 *   [ u16 clen ][ ciphertext (clen bytes, = plaintext_len + WLD_TAG_LEN) ]
 * The 2-byte length is authenticated as AEAD associated data.
 * A record whose plaintext length is 0 is a keepalive.
 */
#define WLD_REC_MAX_PLAIN   16384
#define WLD_REC_HDR_LEN     2
#define WLD_REC_MAX_CIPHER  (WLD_REC_MAX_PLAIN + WLD_TAG_LEN)

static inline const char *
wld_err_str(int code)
{
	switch (code) {
	case WLD_E_INUSE:    return "address already in use by a listener";
	case WLD_E_NOSRV:    return "no peer is listening on this address";
	case WLD_E_BADTOKEN: return "listen token mismatch";
	case WLD_E_PROTO:    return "protocol error";
	case WLD_E_BUSY:     return "relay is at capacity";
	default:             return "unknown error";
	}
}

#endif /* WLD_PROTO_H */
