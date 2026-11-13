/*
 * wetland — crypto core
 *
 * Secret derivation and the end-to-end handshake/transport.
 *
 * Design (see README.md "Security" for rationale):
 *   - A single shared secret derives everything via HKDF-SHA256 with
 *     domain-separation salts.
 *   - The E2E session uses an authenticated key exchange modelled on the
 *     Noise "NNpsk0" pattern: ephemeral X25519 Diffie-Hellman mixed with the
 *     pre-shared key (PSK) through HKDF, followed by explicit key confirmation.
 *   - The transport is ChaCha20-Poly1305 AEAD with per-direction 64-bit
 *     counters. The relay only ever sees ciphertext.
 */
#ifndef WLD_CRYPTO_H
#define WLD_CRYPTO_H 1

#include <stdint.h>
#include <stddef.h>

#define WLD_KEY_LEN     32   /* ChaCha20-Poly1305 / HKDF output key */
#define WLD_NONCE_LEN   12   /* ChaCha20-Poly1305 IETF nonce        */
#define WLD_TAG_LEN     16   /* Poly1305 tag                        */
#define WLD_DH_LEN      32   /* X25519 public key / shared secret   */
#define WLD_ADDR_LEN    16   /* rendezvous address                  */
#define WLD_TOKEN_LEN   16   /* listen-slot ownership token         */
#define WLD_PSK_LEN     32   /* pre-shared key derived from secret  */

/* One direction of an established session. */
typedef struct {
	uint8_t  key[WLD_KEY_LEN];
	uint64_t counter;          /* next nonce counter (abort on wrap) */
} wld_dir_key;

typedef struct {
	wld_dir_key tx;            /* keys we encrypt with  */
	wld_dir_key rx;            /* keys we decrypt with  */
} wld_session;

/* Must be called once before anything else. Returns 0 on success. */
int wld_crypto_init(void);

/*
 * Derive the rendezvous address, PSK and ownership token from the user secret.
 * `epoch` enables a time-rotating address (0 = static, like gsocket).
 * Any of the output pointers may be NULL if not needed.
 */
int wld_derive(const char *secret, uint64_t epoch,
               uint8_t addr[WLD_ADDR_LEN],
               uint8_t psk[WLD_PSK_LEN],
               uint8_t token[WLD_TOKEN_LEN]);

/*
 * Run the E2E handshake over a *blocking* connected socket `fd`.
 * The connector is the initiator (is_initiator=1), the listener the responder.
 * On success fills `sess` with transport keys. Returns 0 on success,
 * -1 on I/O error, -2 on authentication failure (wrong secret or MITM).
 */
int wld_handshake(int fd, int is_initiator, const uint8_t psk[WLD_PSK_LEN],
                  wld_session *sess);

/*
 * AEAD helpers. `aad`/`aad_len` may be 0. For seal, `out` must hold
 * pt_len + WLD_TAG_LEN bytes. For open, `ct_len` includes the trailing tag and
 * `out` must hold ct_len - WLD_TAG_LEN bytes. open() returns -1 on auth failure.
 */
int wld_aead_seal(const uint8_t key[WLD_KEY_LEN], const uint8_t nonce[WLD_NONCE_LEN],
                  const uint8_t *aad, size_t aad_len,
                  const uint8_t *pt, size_t pt_len, uint8_t *out);
int wld_aead_open(const uint8_t key[WLD_KEY_LEN], const uint8_t nonce[WLD_NONCE_LEN],
                  const uint8_t *aad, size_t aad_len,
                  const uint8_t *ct, size_t ct_len, uint8_t *out);

/* Build a 12-byte IETF nonce from a 64-bit counter (big-endian in low 8 bytes). */
void wld_nonce_from_counter(uint64_t counter, uint8_t nonce[WLD_NONCE_LEN]);

/* Fill buf with cryptographically secure random bytes. Returns 0 on success. */
int wld_random(void *buf, size_t len);

#endif /* WLD_CRYPTO_H */
