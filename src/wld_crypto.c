#include "wld_crypto.h"
#include "wld_net.h"

#include <string.h>
#include <stdio.h>

#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <openssl/core_names.h>
#include <openssl/err.h>

/* Domain-separation salts: changing any of these changes the whole key schedule. */
static const char SALT_PSK[]   = "wetland/psk/v1";
static const char SALT_ADDR[]  = "wetland/addr/v1";
static const char SALT_TOKEN[] = "wetland/token/v1";
static const char HS_PREFIX[]  = "wetland-handshake-v1";

int
wld_crypto_init(void)
{
	/* OpenSSL 3 self-initialises; make sure the RNG is seeded. */
	uint8_t probe;
	if (RAND_bytes(&probe, 1) != 1)
		return -1;
	return 0;
}

int
wld_random(void *buf, size_t len)
{
	return RAND_bytes(buf, (int)len) == 1 ? 0 : -1;
}

void
wld_nonce_from_counter(uint64_t counter, uint8_t nonce[WLD_NONCE_LEN])
{
	memset(nonce, 0, WLD_NONCE_LEN);
	/* big-endian counter in the low 8 bytes */
	for (int i = 0; i < 8; i++)
		nonce[WLD_NONCE_LEN - 1 - i] = (uint8_t)(counter >> (8 * i));
}

/* ---- HKDF-SHA256 (extract + expand), via EVP_KDF ------------------------- */

static int
hkdf(int mode, const uint8_t *key, size_t key_len,
     const uint8_t *salt, size_t salt_len,
     const uint8_t *info, size_t info_len,
     uint8_t *out, size_t out_len)
{
	EVP_KDF *kdf = EVP_KDF_fetch(NULL, "HKDF", NULL);
	if (kdf == NULL)
		return -1;
	EVP_KDF_CTX *ctx = EVP_KDF_CTX_new(kdf);
	EVP_KDF_free(kdf);
	if (ctx == NULL)
		return -1;

	OSSL_PARAM params[6];
	int n = 0;
	int m = mode;
	params[n++] = OSSL_PARAM_construct_int(OSSL_KDF_PARAM_MODE, &m);
	params[n++] = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST, "SHA256", 0);
	params[n++] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_KEY, (void *)key, key_len);
	if (salt != NULL)
		params[n++] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SALT, (void *)salt, salt_len);
	if (info != NULL)
		params[n++] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_INFO, (void *)info, info_len);
	params[n] = OSSL_PARAM_construct_end();

	int rc = EVP_KDF_derive(ctx, out, out_len, params);
	EVP_KDF_CTX_free(ctx);
	return rc == 1 ? 0 : -1;
}

static int
hkdf_extract(const uint8_t *salt, size_t salt_len,
             const uint8_t *ikm, size_t ikm_len, uint8_t prk[32])
{
	return hkdf(EVP_KDF_HKDF_MODE_EXTRACT_ONLY, ikm, ikm_len,
	           salt, salt_len, NULL, 0, prk, 32);
}

static int
hkdf_expand(const uint8_t prk[32], const char *label,
            uint8_t *out, size_t out_len)
{
	return hkdf(EVP_KDF_HKDF_MODE_EXPAND_ONLY, prk, 32,
	           NULL, 0, (const uint8_t *)label, strlen(label), out, out_len);
}

/* Full HKDF (extract+expand) used for the secret -> material derivation. */
static int
hkdf_full(const char *salt, const uint8_t *info, size_t info_len,
          const char *secret, uint8_t *out, size_t out_len)
{
	return hkdf(EVP_KDF_HKDF_MODE_EXTRACT_AND_EXPAND,
	           (const uint8_t *)secret, strlen(secret),
	           (const uint8_t *)salt, strlen(salt),
	           info, info_len, out, out_len);
}

int
wld_derive(const char *secret, uint64_t epoch,
           uint8_t addr[WLD_ADDR_LEN], uint8_t psk[WLD_PSK_LEN],
           uint8_t token[WLD_TOKEN_LEN])
{
	if (psk != NULL) {
		if (hkdf_full(SALT_PSK, NULL, 0, secret, psk, WLD_PSK_LEN) != 0)
			return -1;
	}
	if (addr != NULL) {
		uint8_t ebuf[8];
		for (int i = 0; i < 8; i++)
			ebuf[i] = (uint8_t)(epoch >> (8 * (7 - i)));
		if (hkdf_full(SALT_ADDR, ebuf, sizeof ebuf, secret, addr, WLD_ADDR_LEN) != 0)
			return -1;
	}
	if (token != NULL) {
		if (hkdf_full(SALT_TOKEN, NULL, 0, secret, token, WLD_TOKEN_LEN) != 0)
			return -1;
	}
	return 0;
}

/* ---- AEAD: ChaCha20-Poly1305 -------------------------------------------- */

int
wld_aead_seal(const uint8_t key[WLD_KEY_LEN], const uint8_t nonce[WLD_NONCE_LEN],
              const uint8_t *aad, size_t aad_len,
              const uint8_t *pt, size_t pt_len, uint8_t *out)
{
	EVP_CIPHER_CTX *c = EVP_CIPHER_CTX_new();
	if (c == NULL)
		return -1;
	int ok = 0, len = 0;
	if (EVP_EncryptInit_ex(c, EVP_chacha20_poly1305(), NULL, NULL, NULL) != 1)
		goto done;
	if (EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_AEAD_SET_IVLEN, WLD_NONCE_LEN, NULL) != 1)
		goto done;
	if (EVP_EncryptInit_ex(c, NULL, NULL, key, nonce) != 1)
		goto done;
	if (aad != NULL && aad_len > 0)
		if (EVP_EncryptUpdate(c, NULL, &len, aad, (int)aad_len) != 1)
			goto done;
	if (pt_len > 0)
		if (EVP_EncryptUpdate(c, out, &len, pt, (int)pt_len) != 1)
			goto done;
	int flen = 0;
	if (EVP_EncryptFinal_ex(c, out + len, &flen) != 1)
		goto done;
	if (EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_AEAD_GET_TAG, WLD_TAG_LEN, out + pt_len) != 1)
		goto done;
	ok = 1;
done:
	EVP_CIPHER_CTX_free(c);
	return ok ? 0 : -1;
}

int
wld_aead_open(const uint8_t key[WLD_KEY_LEN], const uint8_t nonce[WLD_NONCE_LEN],
              const uint8_t *aad, size_t aad_len,
              const uint8_t *ct, size_t ct_len, uint8_t *out)
{
	if (ct_len < WLD_TAG_LEN)
		return -1;
	size_t body = ct_len - WLD_TAG_LEN;
	EVP_CIPHER_CTX *c = EVP_CIPHER_CTX_new();
	if (c == NULL)
		return -1;
	int ok = 0, len = 0;
	if (EVP_DecryptInit_ex(c, EVP_chacha20_poly1305(), NULL, NULL, NULL) != 1)
		goto done;
	if (EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_AEAD_SET_IVLEN, WLD_NONCE_LEN, NULL) != 1)
		goto done;
	if (EVP_DecryptInit_ex(c, NULL, NULL, key, nonce) != 1)
		goto done;
	if (aad != NULL && aad_len > 0)
		if (EVP_DecryptUpdate(c, NULL, &len, aad, (int)aad_len) != 1)
			goto done;
	if (body > 0)
		if (EVP_DecryptUpdate(c, out, &len, ct, (int)body) != 1)
			goto done;
	if (EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_AEAD_SET_TAG, WLD_TAG_LEN,
	                        (void *)(ct + body)) != 1)
		goto done;
	int flen = 0;
	if (EVP_DecryptFinal_ex(c, out + len, &flen) != 1)
		goto done; /* authentication failed */
	ok = 1;
done:
	EVP_CIPHER_CTX_free(c);
	return ok ? 0 : -1;
}

/* ---- X25519 ------------------------------------------------------------- */

static EVP_PKEY *
x25519_keygen(uint8_t pub[WLD_DH_LEN])
{
	EVP_PKEY *pkey = EVP_PKEY_Q_keygen(NULL, NULL, "X25519");
	if (pkey == NULL)
		return NULL;
	size_t publen = WLD_DH_LEN;
	if (EVP_PKEY_get_raw_public_key(pkey, pub, &publen) != 1 || publen != WLD_DH_LEN) {
		EVP_PKEY_free(pkey);
		return NULL;
	}
	return pkey;
}

static int
x25519_derive(EVP_PKEY *mine, const uint8_t peer_pub[WLD_DH_LEN], uint8_t out[WLD_DH_LEN])
{
	EVP_PKEY *peer = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, NULL,
	                                             peer_pub, WLD_DH_LEN);
	if (peer == NULL)
		return -1;
	EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(mine, NULL);
	int ok = 0;
	size_t outlen = WLD_DH_LEN;
	if (ctx == NULL)
		goto done;
	if (EVP_PKEY_derive_init(ctx) != 1)
		goto done;
	if (EVP_PKEY_derive_set_peer(ctx, peer) != 1)
		goto done;
	if (EVP_PKEY_derive(ctx, out, &outlen) != 1 || outlen != WLD_DH_LEN)
		goto done;
	ok = 1;
done:
	EVP_PKEY_CTX_free(ctx);
	EVP_PKEY_free(peer);
	return ok ? 0 : -1;
}

/* ---- Handshake (Noise_NNpsk0-style) ------------------------------------- *
 *
 * Wire exchange (over the already-paired, blocking tunnel fd):
 *   initiator -> responder:  e_pub_i   (32 bytes)
 *   responder -> initiator:  e_pub_r   (32 bytes)
 *   initiator -> responder:  confirm_i (16-byte AEAD tag over transcript)
 *   responder -> initiator:  confirm_r (16-byte AEAD tag over transcript)
 *
 * Key schedule:
 *   dh   = X25519(e_priv_self, e_pub_peer)
 *   h    = SHA256(HS_PREFIX || e_pub_i || e_pub_r)
 *   prk  = HKDF-Extract(salt = h, ikm = dh || psk)
 *   k_i2r / k_r2i / kc_i2r / kc_r2i = HKDF-Expand(prk, <label>, 32)
 *
 * The confirmation tags are AEAD(kc_dir, nonce=0, aad=h, plaintext="").
 * An attacker without the PSK derives a different prk and cannot produce a
 * verifying tag, so an active MITM is detected and both ends abort.
 */
int
wld_handshake(int fd, int is_initiator, const uint8_t psk[WLD_PSK_LEN],
              wld_session *sess)
{
	uint8_t pub[WLD_DH_LEN], peer_pub[WLD_DH_LEN];
	EVP_PKEY *mine = x25519_keygen(pub);
	if (mine == NULL)
		return -1;

	int rc = -1;

	/* 1) exchange ephemeral public keys */
	if (is_initiator) {
		if (wld_write_all(fd, pub, sizeof pub) != 0)
			goto io_fail;
		if (wld_read_all(fd, peer_pub, sizeof peer_pub) != 0)
			goto io_fail;
	} else {
		if (wld_read_all(fd, peer_pub, sizeof peer_pub) != 0)
			goto io_fail;
		if (wld_write_all(fd, pub, sizeof pub) != 0)
			goto io_fail;
	}

	/* 2) DH + transcript hash */
	uint8_t dh[WLD_DH_LEN];
	if (x25519_derive(mine, peer_pub, dh) != 0)
		goto fail;

	const uint8_t *epub_i = is_initiator ? pub : peer_pub;
	const uint8_t *epub_r = is_initiator ? peer_pub : pub;

	uint8_t h[SHA256_DIGEST_LENGTH];
	{
		uint8_t tbuf[sizeof HS_PREFIX - 1 + 2 * WLD_DH_LEN];
		size_t o = 0;
		memcpy(tbuf + o, HS_PREFIX, sizeof HS_PREFIX - 1); o += sizeof HS_PREFIX - 1;
		memcpy(tbuf + o, epub_i, WLD_DH_LEN); o += WLD_DH_LEN;
		memcpy(tbuf + o, epub_r, WLD_DH_LEN); o += WLD_DH_LEN;
		size_t hlen = sizeof h;
		if (EVP_Q_digest(NULL, "SHA256", NULL, tbuf, o, h, &hlen) != 1)
			goto fail;
	}

	/* 3) key schedule */
	uint8_t ikm[WLD_DH_LEN + WLD_PSK_LEN];
	memcpy(ikm, dh, WLD_DH_LEN);
	memcpy(ikm + WLD_DH_LEN, psk, WLD_PSK_LEN);

	uint8_t prk[32];
	if (hkdf_extract(h, sizeof h, ikm, sizeof ikm, prk) != 0)
		goto fail;

	uint8_t k_i2r[32], k_r2i[32], kc_i2r[32], kc_r2i[32];
	if (hkdf_expand(prk, "wld-data-i2r", k_i2r, 32) != 0 ||
	    hkdf_expand(prk, "wld-data-r2i", k_r2i, 32) != 0 ||
	    hkdf_expand(prk, "wld-conf-i2r", kc_i2r, 32) != 0 ||
	    hkdf_expand(prk, "wld-conf-r2i", kc_r2i, 32) != 0)
		goto fail;

	/* 4) key confirmation (empty-plaintext AEAD over transcript h) */
	uint8_t zero_nonce[WLD_NONCE_LEN];
	wld_nonce_from_counter(0, zero_nonce);

	uint8_t my_conf[WLD_TAG_LEN], peer_conf[WLD_TAG_LEN];
	const uint8_t *my_conf_key   = is_initiator ? kc_i2r : kc_r2i;
	const uint8_t *peer_conf_key = is_initiator ? kc_r2i : kc_i2r;

	if (wld_aead_seal(my_conf_key, zero_nonce, h, sizeof h, NULL, 0, my_conf) != 0)
		goto fail;

	if (is_initiator) {
		if (wld_write_all(fd, my_conf, sizeof my_conf) != 0)
			goto io_fail;
		if (wld_read_all(fd, peer_conf, sizeof peer_conf) != 0)
			goto io_fail;
	} else {
		if (wld_read_all(fd, peer_conf, sizeof peer_conf) != 0)
			goto io_fail;
		if (wld_write_all(fd, my_conf, sizeof my_conf) != 0)
			goto io_fail;
	}

	/* verify peer's confirmation (empty plaintext -> ct is just the tag) */
	uint8_t scratch;
	(void)scratch;
	if (wld_aead_open(peer_conf_key, zero_nonce, h, sizeof h,
	                  peer_conf, WLD_TAG_LEN, NULL) != 0) {
		rc = -2; /* auth failure: wrong secret or active MITM */
		goto fail;
	}

	/* 5) install transport keys (confirmation used its own keys, so start at 0) */
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

	/* wipe sensitive stack material */
	OPENSSL_cleanse(dh, sizeof dh);
	OPENSSL_cleanse(ikm, sizeof ikm);
	OPENSSL_cleanse(prk, sizeof prk);
	OPENSSL_cleanse(k_i2r, sizeof k_i2r);
	OPENSSL_cleanse(k_r2i, sizeof k_r2i);
	OPENSSL_cleanse(kc_i2r, sizeof kc_i2r);
	OPENSSL_cleanse(kc_r2i, sizeof kc_r2i);
	EVP_PKEY_free(mine);
	return rc;

io_fail:
	rc = -1;
fail:
	EVP_PKEY_free(mine);
	return rc;
}
