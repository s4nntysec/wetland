#include "wld_tunnel.h"
#include "wld_net.h"
#include "wld_proto.h"
#include "wld_compat.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef _WIN32  /* ===================== POSIX pump (poll) ===================== */

#include <errno.h>
#include <poll.h>
#include <unistd.h>
#include <sys/socket.h>

/* ---- tiny linear growable byte buffer ----------------------------------- */
typedef struct {
	uint8_t *data;
	size_t   cap;   /* allocated                         */
	size_t   off;   /* start of valid region             */
	size_t   len;   /* bytes of valid data from off      */
} buf_t;

static int
buf_init(buf_t *b, size_t cap)
{
	b->data = malloc(cap);
	if (b->data == NULL)
		return -1;
	b->cap = cap;
	b->off = 0;
	b->len = 0;
	return 0;
}

static void
buf_free(buf_t *b)
{
	free(b->data);
	b->data = NULL;
}

static uint8_t *
buf_head(buf_t *b) { return b->data + b->off; }

static size_t
buf_tailroom(buf_t *b) { return b->cap - (b->off + b->len); }

static void
buf_compact(buf_t *b)
{
	if (b->off == 0)
		return;
	if (b->len > 0)
		memmove(b->data, b->data + b->off, b->len);
	b->off = 0;
}

static void
buf_consume(buf_t *b, size_t n)
{
	b->off += n;
	b->len -= n;
	if (b->len == 0)
		b->off = 0;
}

static int
buf_append(buf_t *b, const uint8_t *src, size_t n)
{
	if (buf_tailroom(b) < n)
		buf_compact(b);
	if (buf_tailroom(b) < n)
		return -1;
	memcpy(b->data + b->off + b->len, src, n);
	b->len += n;
	return 0;
}

/* ---- framing ------------------------------------------------------------ */

/* Seal plaintext as a [u16 len][ciphertext] record into tx. */
static int
seal_record(buf_t *tx, wld_dir_key *k, const uint8_t *pt, size_t pt_len)
{
	if (k->counter == UINT64_MAX)
		return -1; /* nonce space exhausted */
	uint8_t nonce[WLD_NONCE_LEN];
	wld_nonce_from_counter(k->counter, nonce);

	size_t clen = pt_len + WLD_TAG_LEN;
	uint8_t hdr[WLD_REC_HDR_LEN] = { (uint8_t)(clen >> 8), (uint8_t)(clen & 0xff) };
	uint8_t cipher[WLD_REC_MAX_CIPHER];

	/* associated data = the 2-byte length header */
	if (wld_aead_seal(k->key, nonce, hdr, sizeof hdr, pt, pt_len, cipher) != 0)
		return -1;
	k->counter++;

	if (buf_append(tx, hdr, sizeof hdr) != 0)
		return -1;
	if (buf_append(tx, cipher, clen) != 0)
		return -1;
	return 0;
}

/* Try to open one record from rx_cipher into rx_plain.
 * Returns 1 if a record was processed, 0 if more data needed, -1 on error. */
static int
open_record(buf_t *rxc, buf_t *rxp, wld_dir_key *k)
{
	if (rxc->len < WLD_REC_HDR_LEN)
		return 0;
	uint8_t *h = buf_head(rxc);
	size_t clen = ((size_t)h[0] << 8) | h[1];
	if (clen < WLD_TAG_LEN || clen > WLD_REC_MAX_CIPHER)
		return -1; /* framing error */
	if (rxc->len < WLD_REC_HDR_LEN + clen)
		return 0;  /* wait for the rest */

	size_t pt_len = clen - WLD_TAG_LEN;
	if (buf_tailroom(rxp) < pt_len)
		buf_compact(rxp);
	if (buf_tailroom(rxp) < pt_len)
		return 0;  /* backpressure: drain rx_plain first */

	uint8_t nonce[WLD_NONCE_LEN];
	wld_nonce_from_counter(k->counter, nonce);

	uint8_t hdr[WLD_REC_HDR_LEN] = { h[0], h[1] };
	uint8_t *ct = h + WLD_REC_HDR_LEN;
	uint8_t *out = rxp->data + rxp->off + rxp->len;
	if (wld_aead_open(k->key, nonce, hdr, sizeof hdr, ct, clen, out) != 0)
		return -1; /* authentication failure */
	k->counter++;
	rxp->len += pt_len;
	buf_consume(rxc, WLD_REC_HDR_LEN + clen);
	return 1;
}

/* ---- the pump ----------------------------------------------------------- */

int
wld_pump(int tun_fd, int local_rd, int local_wr, wld_session *sess)
{
	int rc = -1;
	buf_t txc, rxc, rxp; /* tx ciphertext, rx ciphertext, rx plaintext */
	uint8_t staging[WLD_REC_MAX_PLAIN];

	if (buf_init(&txc, 4 * WLD_REC_MAX_CIPHER) != 0)
		return -1;
	if (buf_init(&rxc, 4 * WLD_REC_MAX_CIPHER) != 0) { buf_free(&txc); return -1; }
	if (buf_init(&rxp, 4 * WLD_REC_MAX_PLAIN) != 0) { buf_free(&txc); buf_free(&rxc); return -1; }

	wld_set_nonblock(tun_fd, 1);
	wld_set_nonblock(local_rd, 1);
	if (local_wr != local_rd)
		wld_set_nonblock(local_wr, 1);

	int local_read_eof = 0;  /* cleartext input finished            */
	int tun_read_eof = 0;    /* no more encrypted data from peer     */
	int tun_wr_shut = 0;     /* we've sent FIN on the tunnel         */
	int local_wr_shut = 0;   /* we've signalled EOF to local side    */

	for (;;) {
		/* Drain any fully-received records before deciding on poll flags. */
		for (;;) {
			int r = open_record(&rxc, &rxp, &sess->rx);
			if (r < 0)
				goto out;       /* auth / framing error */
			if (r == 0)  break;
		}
		/* Compact so free space is contiguous at the tail: otherwise a
		 * partially-received record parked at a high offset can leave
		 * buf_tailroom()==0 even though the buffer is far from full, which
		 * would wrongly suppress the tunnel read and stall the pump. */
		buf_compact(&rxc);

		struct pollfd pfd[3];
		int n = 0;
		int i_tun = -1, i_lrd = -1, i_lwr = -1;

		/* tunnel: read if we can buffer more; write if we have ciphertext */
		short tev = 0;
		if (!tun_read_eof && buf_tailroom(&rxc) > 0)
			tev |= POLLIN;
		if (txc.len > 0)
			tev |= POLLOUT;
		if (tev) { pfd[n].fd = tun_fd; pfd[n].events = tev; i_tun = n++; }

		/* local read: into staging -> sealed into txc (bound the backlog) */
		if (!local_read_eof && txc.len < 2 * WLD_REC_MAX_CIPHER) {
			pfd[n].fd = local_rd; pfd[n].events = POLLIN; i_lrd = n++;
		}

		/* local write: flush decrypted plaintext */
		if (rxp.len > 0) {
			pfd[n].fd = local_wr; pfd[n].events = POLLOUT; i_lwr = n++;
		}

		/* Termination: input done, nothing left to send, peer done, nothing
		 * left to deliver locally. */
		if (local_read_eof && txc.len == 0 && tun_read_eof && rxp.len == 0) {
			rc = 0;
			goto out;
		}

		if (n == 0) {
			/* Nothing to wait on — we are done. */
			rc = 0;
			goto out;
		}

		int pr = poll(pfd, n, -1);
		if (pr < 0) {
			if (errno == EINTR)
				continue;
			goto out;
		}

		/* --- tunnel writable: flush ciphertext --- */
		if (i_tun >= 0 && (pfd[i_tun].revents & POLLOUT)) {
			ssize_t w = write(tun_fd, buf_head(&txc), txc.len);
			if (w > 0)
				buf_consume(&txc, (size_t)w);
			else if (w < 0 && errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR)
				goto out;
		}

		/* --- tunnel readable: pull ciphertext --- */
		if (i_tun >= 0 && (pfd[i_tun].revents & (POLLIN | POLLHUP))) {
			buf_compact(&rxc);
			ssize_t r = read(tun_fd, buf_head(&rxc) + rxc.len, buf_tailroom(&rxc));
			if (r > 0)
				rxc.len += (size_t)r;
			else if (r == 0)
				tun_read_eof = 1;
			else if (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR)
				goto out;
		}

		/* --- local readable: seal into txc --- */
		if (i_lrd >= 0 && (pfd[i_lrd].revents & (POLLIN | POLLHUP))) {
			ssize_t r = read(local_rd, staging, sizeof staging);
			if (r > 0) {
				if (seal_record(&txc, &sess->tx, staging, (size_t)r) != 0)
					goto out;
			} else if (r == 0) {
				local_read_eof = 1;
			} else if (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR) {
				goto out;
			}
		}

		/* --- local writable: flush plaintext --- */
		if (i_lwr >= 0 && (pfd[i_lwr].revents & POLLOUT)) {
			ssize_t w = write(local_wr, buf_head(&rxp), rxp.len);
			if (w > 0)
				buf_consume(&rxp, (size_t)w);
			else if (w < 0 && errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR)
				goto out;
		}

		/* Once local input is done and all ciphertext flushed, half-close the
		 * tunnel so the peer observes EOF. */
		if (local_read_eof && txc.len == 0 && !tun_wr_shut) {
			shutdown(tun_fd, SHUT_WR);
			tun_wr_shut = 1;
		}
		/* Once the peer is done and everything delivered, signal EOF to the
		 * local side. For a socketpair (exec mode) this is a half-close that
		 * still lets us read the command's output; for a plain pipe/file the
		 * shutdown is a harmless no-op (ENOTSOCK). */
		if (tun_read_eof && rxp.len == 0 && !local_wr_shut) {
			shutdown(local_wr, SHUT_WR);
			local_wr_shut = 1;
		}
	}

out:
	buf_free(&txc);
	buf_free(&rxc);
	buf_free(&rxp);
	return rc;
}

#else  /* ===================== Windows pump (threads) ===================== */

#include <windows.h>
#include <process.h>
#include <io.h>

/*
 * WSAPoll works only on sockets, not on stdin/stdout/pipes, so on Windows we
 * use two blocking threads: one seals local input into tunnel records, the
 * other opens tunnel records into local output. Suited to pipe/file transfer;
 * fully interactive console I/O is a known limitation (see README).
 */
struct winpump {
	int tun, local_rd, local_wr;
	wld_session *sess;
};

static unsigned __stdcall
win_tx(void *arg)
{
	struct winpump *w = arg;
	uint8_t staging[WLD_REC_MAX_PLAIN];
	uint8_t cipher[WLD_REC_MAX_CIPHER];
	for (;;) {
		int n = _read(w->local_rd, staging, sizeof staging);
		if (n <= 0)
			break;
		if (w->sess->tx.counter == UINT64_MAX)
			break;
		uint8_t nonce[WLD_NONCE_LEN];
		wld_nonce_from_counter(w->sess->tx.counter, nonce);
		size_t clen = (size_t)n + WLD_TAG_LEN;
		uint8_t hdr[2] = { (uint8_t)(clen >> 8), (uint8_t)(clen & 0xff) };
		if (wld_aead_seal(w->sess->tx.key, nonce, hdr, 2, staging, n, cipher) != 0)
			break;
		w->sess->tx.counter++;
		if (wld_write_all(w->tun, hdr, 2) != 0) break;
		if (wld_write_all(w->tun, cipher, clen) != 0) break;
	}
	shutdown((SOCKET_CAST)w->tun, SHUT_WR);
	return 0;
}

static unsigned __stdcall
win_rx(void *arg)
{
	struct winpump *w = arg;
	uint8_t cipher[WLD_REC_MAX_CIPHER];
	uint8_t plain[WLD_REC_MAX_PLAIN];
	for (;;) {
		uint8_t hdr[2];
		if (wld_read_all(w->tun, hdr, 2) != 0)
			break;
		size_t clen = ((size_t)hdr[0] << 8) | hdr[1];
		if (clen < WLD_TAG_LEN || clen > WLD_REC_MAX_CIPHER)
			break;
		if (wld_read_all(w->tun, cipher, clen) != 0)
			break;
		uint8_t nonce[WLD_NONCE_LEN];
		wld_nonce_from_counter(w->sess->rx.counter, nonce);
		if (wld_aead_open(w->sess->rx.key, nonce, hdr, 2, cipher, clen, plain) != 0)
			break;
		w->sess->rx.counter++;
		size_t pt_len = clen - WLD_TAG_LEN;
		size_t off = 0;
		while (off < pt_len) {
			int wn = _write(w->local_wr, plain + off, (unsigned)(pt_len - off));
			if (wn <= 0) { off = pt_len; break; }
			off += (size_t)wn;
		}
	}
	return 0;
}

int
wld_pump(int tun_fd, int local_rd, int local_wr, wld_session *sess)
{
	struct winpump w = { tun_fd, local_rd, local_wr, sess };
	HANDLE th[2];
	th[0] = (HANDLE)_beginthreadex(NULL, 0, win_tx, &w, 0, NULL);
	th[1] = (HANDLE)_beginthreadex(NULL, 0, win_rx, &w, 0, NULL);
	if (th[0] == NULL || th[1] == NULL)
		return -1;

	/* The rx thread (tunnel -> local) defines the session lifetime: it returns
	 * when the peer closes, after delivering everything. Wait for it fully, then
	 * give tx a short grace (a tx thread blocked on console input with no EOF is
	 * abandoned at process exit — a known interactive limitation on Windows). */
	WaitForSingleObject(th[1], INFINITE);
	WaitForSingleObject(th[0], 2000);
	CloseHandle(th[0]);
	CloseHandle(th[1]);
	return 0;
}

#endif  /* _WIN32 */
