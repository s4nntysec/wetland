/* wetland — crypto unit tests */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "wld_crypto.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/wait.h>

static int failures;
#define CHECK(cond, msg) do { \
	if (cond) { printf("  ok   %s\n", msg); } \
	else { printf("  FAIL %s\n", msg); failures++; } \
} while (0)

static void
test_derive(void)
{
	printf("derivation:\n");
	uint8_t a1[16], p1[32], t1[16];
	uint8_t a2[16], p2[32], t2[16];
	uint8_t a3[16], p3[32], t3[16];

	wld_derive("hunter2", 0, a1, p1, t1);
	wld_derive("hunter2", 0, a2, p2, t2);
	wld_derive("different", 0, a3, p3, t3);

	CHECK(memcmp(a1, a2, 16) == 0, "same secret -> same address");
	CHECK(memcmp(p1, p2, 32) == 0, "same secret -> same psk");
	CHECK(memcmp(t1, t2, 16) == 0, "same secret -> same token");
	CHECK(memcmp(a1, a3, 16) != 0, "different secret -> different address");
	CHECK(memcmp(p1, p3, 32) != 0, "different secret -> different psk");
	CHECK(memcmp(a1, p1, 16) != 0, "address != psk prefix (domain separation)");

	/* epoch rotation changes the address but not the psk/token */
	uint8_t ae1[16], ae2[16];
	wld_derive("hunter2", 100, ae1, NULL, NULL);
	wld_derive("hunter2", 101, ae2, NULL, NULL);
	CHECK(memcmp(ae1, ae2, 16) != 0, "different epoch -> different address");
	CHECK(memcmp(ae1, a1, 16) != 0, "epoch addr != static addr");
}

static void
test_aead(void)
{
	printf("aead:\n");
	uint8_t key[32], nonce[12];
	memset(key, 0x42, sizeof key);
	wld_nonce_from_counter(1, nonce);

	const char *pt = "the relay sees only ciphertext";
	size_t ptlen = strlen(pt);
	uint8_t ct[256], out[256];
	uint8_t aad[2] = { 0x00, 0x30 };

	CHECK(wld_aead_seal(key, nonce, aad, sizeof aad, (const uint8_t *)pt, ptlen, ct) == 0,
	    "seal");
	CHECK(wld_aead_open(key, nonce, aad, sizeof aad, ct, ptlen + 16, out) == 0,
	    "open roundtrip");
	CHECK(memcmp(out, pt, ptlen) == 0, "plaintext recovered");

	/* tamper */
	ct[0] ^= 0x01;
	CHECK(wld_aead_open(key, nonce, aad, sizeof aad, ct, ptlen + 16, out) != 0,
	    "tampered ciphertext rejected");
	ct[0] ^= 0x01;

	/* wrong aad */
	aad[0] ^= 0x01;
	CHECK(wld_aead_open(key, nonce, aad, sizeof aad, ct, ptlen + 16, out) != 0,
	    "wrong aad rejected");
	aad[0] ^= 0x01;

	/* wrong nonce */
	uint8_t n2[12];
	wld_nonce_from_counter(2, n2);
	CHECK(wld_aead_open(key, n2, aad, sizeof aad, ct, ptlen + 16, out) != 0,
	    "wrong nonce rejected");
}

/* Run a handshake over a socketpair. Responder runs in a child process.
 * Returns parent's handshake rc; *child_rc gets the child's. */
static int
run_handshake(const uint8_t psk_init[32], const uint8_t psk_resp[32],
              int do_roundtrip, int *child_rc)
{
	int sv[2];
	if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) { perror("socketpair"); exit(2); }

	pid_t pid = fork();
	if (pid == 0) {
		close(sv[0]);
		wld_session s;
		int rc = wld_handshake(sv[1], 0 /*responder*/, psk_resp, &s);
		int code = (rc == 0) ? 0 : (rc == -2 ? 2 : 1);
		if (rc == 0 && do_roundtrip) {
			/* responder decrypts one record from initiator (counter 0, rx key) */
			uint8_t nonce[12], buf[64];
			wld_nonce_from_counter(0, nonce);
			uint8_t ct[64];
			if (read(sv[1], ct, 5 + 16) == 5 + 16 &&
			    wld_aead_open(s.rx.key, nonce, NULL, 0, ct, 5 + 16, buf) == 0 &&
			    memcmp(buf, "HELLO", 5) == 0)
				code = 0;
			else
				code = 3;
		}
		close(sv[1]);
		_exit(code);
	}
	close(sv[1]);
	wld_session s;
	int rc = wld_handshake(sv[0], 1 /*initiator*/, psk_init, &s);
	if (rc == 0 && do_roundtrip) {
		uint8_t nonce[12], ct[64];
		wld_nonce_from_counter(0, nonce);
		wld_aead_seal(s.tx.key, nonce, NULL, 0, (const uint8_t *)"HELLO", 5, ct);
		if (write(sv[0], ct, 5 + 16) != 5 + 16) { /* ignore */ }
	}
	close(sv[0]);
	int st = 0;
	waitpid(pid, &st, 0);
	*child_rc = WIFEXITED(st) ? WEXITSTATUS(st) : -1;
	return rc;
}

static void
test_handshake(void)
{
	printf("handshake:\n");
	uint8_t psk[32], psk_bad[32];
	wld_derive("matching-secret", 0, NULL, psk, NULL);
	wld_derive("other-secret", 0, NULL, psk_bad, NULL);

	int child_rc = -1;
	int rc = run_handshake(psk, psk, 1, &child_rc);
	CHECK(rc == 0, "initiator handshake succeeds (matching psk)");
	CHECK(child_rc == 0, "responder handshake + transport roundtrip succeeds");

	rc = run_handshake(psk, psk_bad, 0, &child_rc);
	CHECK(rc != 0, "initiator rejects mismatched psk");
	CHECK(child_rc == 2, "responder reports auth failure (-2) on mismatched psk");
}

int
main(void)
{
	if (wld_crypto_init() != 0) {
		fprintf(stderr, "crypto init failed\n");
		return 2;
	}
	test_derive();
	test_aead();
	test_handshake();

	printf("\n%s (%d failure%s)\n",
	    failures == 0 ? "ALL TESTS PASSED" : "TESTS FAILED",
	    failures, failures == 1 ? "" : "s");
	return failures == 0 ? 0 : 1;
}
