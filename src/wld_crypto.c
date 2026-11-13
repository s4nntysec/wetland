#include "wld_crypto.h"
#include "monocypher/monocypher.h"

#include <string.h>
#include <stdlib.h>

/* ---- OS randomness ------------------------------------------------------- */
#if defined(_WIN32)
#  include <windows.h>
#  include <bcrypt.h>
#elif defined(__APPLE__) || defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__)
#  include <stdlib.h>   /* arc4random_buf */
#else
#  include <sys/random.h> /* getrandom */
#  include <errno.h>
#  include <fcntl.h>
#  include <unistd.h>
#endif

int
wld_random(void *buf, size_t len)
{
#if defined(_WIN32)
	if (BCryptGenRandom(NULL, (PUCHAR)buf, (ULONG)len,
	                    BCRYPT_USE_SYSTEM_PREFERRED_RNG) != 0)
		return -1;
	return 0;
#elif defined(__APPLE__) || defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__)
	arc4random_buf(buf, len);
	return 0;
#else
	uint8_t *p = buf;
	size_t off = 0;
	while (off < len) {
		ssize_t r = getrandom(p + off, len - off, 0);
		if (r < 0) {
			if (errno == EINTR)
				continue;
			break; /* fall back to /dev/urandom */
		}
		off += (size_t)r;
	}
	if (off == len)
		return 0;
	/* fallback */
	int fd = open("/dev/urandom", O_RDONLY);
	if (fd < 0)
		return -1;
	while (off < len) {
		ssize_t r = read(fd, p + off, len - off);
		if (r <= 0) {
			if (r < 0 && errno == EINTR)
				continue;
			close(fd);
			return -1;
		}
		off += (size_t)r;
	}
	close(fd);
	return 0;
#endif
}

int
wld_crypto_init(void)
{
	uint8_t probe;
	return wld_random(&probe, 1);
}

void
wld_wipe(void *buf, size_t len)
{
	crypto_wipe(buf, len);
}

/* Domain-separation salts (used as BLAKE2b keys). */
static const char SALT_PSK[]   = "wetland/psk/v1";
static const char SALT_ADDR[]  = "wetland/addr/v1";
static const char SALT_TOKEN[] = "wetland/token/v1";
static const char HS_PREFIX[]  = "wetland-handshake-v1";

/* Keyed-BLAKE2b PRF: out = BLAKE2b(key, msg). Our standard KDF primitive. */
static void
kdf(uint8_t *out, size_t out_len,
    const uint8_t *key, size_t key_len,
    const uint8_t *msg, size_t msg_len)
{
	crypto_blake2b_keyed(out, out_len, key, key_len, msg, msg_len);
}

void
wld_nonce_from_counter(uint64_t counter, uint8_t nonce[WLD_NONCE_LEN])
{
	memset(nonce, 0, WLD_NONCE_LEN);
	/* big-endian counter in the low 8 bytes */
	for (int i = 0; i < 8; i++)
		nonce[WLD_NONCE_LEN - 1 - i] = (uint8_t)(counter >> (8 * i));
}

int
wld_derive(const char *secret, uint64_t epoch,
           uint8_t addr[WLD_ADDR_LEN], uint8_t psk[WLD_PSK_LEN],
           uint8_t token[WLD_TOKEN_LEN])
{
	size_t slen = strlen(secret);

	if (psk != NULL)
		kdf(psk, WLD_PSK_LEN, (const uint8_t *)SALT_PSK, strlen(SALT_PSK),
		    (const uint8_t *)secret, slen);

	if (token != NULL)
		kdf(token, WLD_TOKEN_LEN, (const uint8_t *)SALT_TOKEN, strlen(SALT_TOKEN),
		    (const uint8_t *)secret, slen);

	if (addr != NULL) {
		/* message = epoch(8, big-endian) || secret */
		uint8_t *msg = malloc(8 + slen);
		if (msg == NULL)
			return -1;
		for (int i = 0; i < 8; i++)
			msg[i] = (uint8_t)(epoch >> (8 * (7 - i)));
		memcpy(msg + 8, secret, slen);
		kdf(addr, WLD_ADDR_LEN, (const uint8_t *)SALT_ADDR, strlen(SALT_ADDR),
		    msg, 8 + slen);
		crypto_wipe(msg, 8 + slen);
		free(msg);
	}
	return 0;
}

/* ---- AEAD: XChaCha20-Poly1305 ------------------------------------------- *
 * Wire layout is [ciphertext][mac(16)] contiguous; Monocypher takes the mac
 * as a separate buffer, so we point it just past the ciphertext. */
int
wld_aead_seal(const uint8_t key[WLD_KEY_LEN], const uint8_t nonce[WLD_NONCE_LEN],
              const uint8_t *aad, size_t aad_len,
              const uint8_t *pt, size_t pt_len, uint8_t *out)
{
	crypto_aead_lock(out, out + pt_len, key, nonce, aad, aad_len, pt, pt_len);
	return 0;
}

int
wld_aead_open(const uint8_t key[WLD_KEY_LEN], const uint8_t nonce[WLD_NONCE_LEN],
              const uint8_t *aad, size_t aad_len,
              const uint8_t *ct, size_t ct_len, uint8_t *out)
{
	if (ct_len < WLD_TAG_LEN)
		return -1;
	size_t body = ct_len - WLD_TAG_LEN;
	return crypto_aead_unlock(out, ct + body, key, nonce, aad, aad_len, ct, body) == 0
	    ? 0 : -1;
}

/* ---- Handshake (Noise_NNpsk0-style) ------------------------------------- *
 *
 * Wire exchange over the already-paired, blocking tunnel fd:
 *   initiator -> responder:  e_pub_i   (32 bytes)
 *   responder -> initiator:  e_pub_r   (32 bytes)
 *   initiator -> responder:  confirm_i (16-byte AEAD tag over transcript)
 *   responder -> initiator:  confirm_r (16-byte AEAD tag over transcript)
 *
 * Key schedule:
 *   dh   = X25519(e_priv_self, e_pub_peer)
 *   h    = BLAKE2b(HS_PREFIX || e_pub_i || e_pub_r)
 *   prk  = BLAKE2b(key = h, msg = dh || psk)
 *   k_i2r / k_r2i / kc_i2r / kc_r2i = BLAKE2b(key = prk, msg = <label>)
 *
 * Confirmation tags are AEAD(kc_dir, nonce=0, ad=h, plaintext="").
 * An attacker without the PSK derives a different prk and cannot produce a
 * verifying tag, so an active MITM is detected and both ends abort.
 */
int
wld_handshake(int fd, int is_initiator, const uint8_t psk[WLD_PSK_LEN],
              wld_session *sess)
{
	/* wld_net.h provides wld_read_all/wld_write_all; declared here to avoid a
	 * circular include and keep crypto self-contained. */
	extern int wld_read_all(int fd, void *buf, size_t n);
	extern int wld_write_all(int fd, const void *buf, size_t n);

	uint8_t sk[WLD_DH_LEN], pub[WLD_DH_LEN], peer_pub[WLD_DH_LEN];
	if (wld_random(sk, sizeof sk) != 0)
		return -1;
	crypto_x25519_public_key(pub, sk);

	int rc = -1;

	/* 1) exchange ephemeral public keys */
	if (is_initiator) {
		if (wld_write_all(fd, pub, sizeof pub) != 0) goto io_fail;
		if (wld_read_all(fd, peer_pub, sizeof peer_pub) != 0) goto io_fail;
	} else {
		if (wld_read_all(fd, peer_pub, sizeof peer_pub) != 0) goto io_fail;
		if (wld_write_all(fd, pub, sizeof pub) != 0) goto io_fail;
	}

	/* 2) DH + transcript hash */
	uint8_t dh[WLD_DH_LEN];
	crypto_x25519(dh, sk, peer_pub);

	const uint8_t *epub_i = is_initiator ? pub : peer_pub;
	const uint8_t *epub_r = is_initiator ? peer_pub : pub;

	uint8_t h[32];
	{
		uint8_t tbuf[sizeof HS_PREFIX - 1 + 2 * WLD_DH_LEN];
		size_t o = 0;
		memcpy(tbuf + o, HS_PREFIX, sizeof HS_PREFIX - 1); o += sizeof HS_PREFIX - 1;
		memcpy(tbuf + o, epub_i, WLD_DH_LEN); o += WLD_DH_LEN;
		memcpy(tbuf + o, epub_r, WLD_DH_LEN); o += WLD_DH_LEN;
		crypto_blake2b(h, sizeof h, tbuf, o);
	}

	/* 3) key schedule */
	uint8_t ikm[WLD_DH_LEN + WLD_PSK_LEN];
	memcpy(ikm, dh, WLD_DH_LEN);
	memcpy(ikm + WLD_DH_LEN, psk, WLD_PSK_LEN);

	uint8_t prk[32];
	kdf(prk, sizeof prk, h, sizeof h, ikm, sizeof ikm);

	uint8_t k_i2r[32], k_r2i[32], kc_i2r[32], kc_r2i[32];
	kdf(k_i2r, 32, prk, 32, (const uint8_t *)"wld-data-i2r", 12);
	kdf(k_r2i, 32, prk, 32, (const uint8_t *)"wld-data-r2i", 12);
	kdf(kc_i2r, 32, prk, 32, (const uint8_t *)"wld-conf-i2r", 12);
	kdf(kc_r2i, 32, prk, 32, (const uint8_t *)"wld-conf-r2i", 12);

	/* 4) key confirmation (empty-plaintext AEAD over transcript h) */
	uint8_t zero_nonce[WLD_NONCE_LEN];
	wld_nonce_from_counter(0, zero_nonce);

	uint8_t my_conf[WLD_TAG_LEN], peer_conf[WLD_TAG_LEN];
	const uint8_t *my_conf_key   = is_initiator ? kc_i2r : kc_r2i;
	const uint8_t *peer_conf_key = is_initiator ? kc_r2i : kc_i2r;

	wld_aead_seal(my_conf_key, zero_nonce, h, sizeof h, NULL, 0, my_conf);

	if (is_initiator) {
		if (wld_write_all(fd, my_conf, sizeof my_conf) != 0) goto io_fail;
		if (wld_read_all(fd, peer_conf, sizeof peer_conf) != 0) goto io_fail;
	} else {
		if (wld_read_all(fd, peer_conf, sizeof peer_conf) != 0) goto io_fail;
		if (wld_write_all(fd, my_conf, sizeof my_conf) != 0) goto io_fail;
	}

	if (wld_aead_open(peer_conf_key, zero_nonce, h, sizeof h,
	                  peer_conf, WLD_TAG_LEN, NULL) != 0) {
		rc = -2; /* auth failure: wrong secret or active MITM */
		goto fail;
	}

	/* 5) install transport keys */
	memset(sess, 0, sizeof *sess);
	if (is_initiator) {
		memcpy(sess->tx.key, k_i2r, 32);
		memcpy(sess->rx.key, k_r2i, 32);
	} else {
		memcpy(sess->tx.key, k_r2i, 32);
		memcpy(sess->rx.key, k_i2r, 32);
	}
	sess->tx.counter = 0;
	sess->rx.counter = 0;
	rc = 0;

fail:
	crypto_wipe(sk, sizeof sk);
	crypto_wipe(dh, sizeof dh);
	crypto_wipe(ikm, sizeof ikm);
	crypto_wipe(prk, sizeof prk);
	crypto_wipe(k_i2r, sizeof k_i2r);
	crypto_wipe(k_r2i, sizeof k_r2i);
	crypto_wipe(kc_i2r, sizeof kc_i2r);
	crypto_wipe(kc_r2i, sizeof kc_r2i);
	return rc;

io_fail:
	crypto_wipe(sk, sizeof sk);
	return -1;
}
