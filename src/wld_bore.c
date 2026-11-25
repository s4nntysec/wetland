/*
 * wetland - bore-style reverse tunnel client (see wld_bore.h).
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "wld_bore.h"
#include "wld_relay.h"
#include "wld_net.h"
#include "wld_compat.h"

#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32

int
wld_bore_autotunnel(const char *bore_host, int requested_port, int verbose,
                    char *local_port_out, size_t lpcap,
                    char *pub_host_out, size_t phcap, int *pub_port_out)
{
	(void)bore_host; (void)requested_port; (void)verbose;
	(void)local_port_out; (void)lpcap; (void)pub_host_out; (void)phcap;
	(void)pub_port_out;
	return -1; /* auto-tunnel is POSIX-only */
}

void wld_bore_drain(int max_ms) { (void)max_ms; }

#else /* ---------------------------------------------------------------- POSIX */

#include <pthread.h>
#include <stdarg.h>
#include <time.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netdb.h>
#include <errno.h>

#define FRAME_MAX 256

static int g_verbose;
static int g_tunnel_up;                 /* set once a tunnel is established   */
static pthread_mutex_t g_amx = PTHREAD_MUTEX_INITIALIZER;
static int g_active;                     /* live proxy connections            */

static void active_inc(void) { pthread_mutex_lock(&g_amx); g_active++; pthread_mutex_unlock(&g_amx); }
static void active_dec(void) { pthread_mutex_lock(&g_amx); g_active--; pthread_mutex_unlock(&g_amx); }
static int  active_get(void) { pthread_mutex_lock(&g_amx); int v = g_active; pthread_mutex_unlock(&g_amx); return v; }

/* TCP connect with a timeout (ms), so an unreachable tunnel server fails fast
 * and with a clear reason instead of blocking far past the startup window. */
static int
connect_to(const char *host, const char *port, int ms)
{
	struct addrinfo hints, *res = NULL, *rp;
	memset(&hints, 0, sizeof hints);
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	if (getaddrinfo(host, port, &hints, &res) != 0) return -2; /* DNS failure */
	int fd = -1;
	for (rp = res; rp != NULL; rp = rp->ai_next) {
		fd = (int)socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
		if (fd < 0) continue;
		wld_set_nonblock(fd, 1);
		int r = connect((SOCKET_CAST)fd, rp->ai_addr, (int)rp->ai_addrlen);
		if (r == 0) { wld_set_nonblock(fd, 0); break; }
		if (errno == EINPROGRESS) {
			wld_pollfd p; p.fd = fd; p.events = POLLOUT;
			if (wld_poll(&p, 1, ms) == 1) {
				int err = 0; socklen_t el = sizeof err;
				getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &el);
				if (err == 0) { wld_set_nonblock(fd, 0); break; }
			}
		}
		wld_closesocket(fd); fd = -1;
	}
	freeaddrinfo(res);
	if (fd >= 0) wld_set_keepalive(fd);
	return fd; /* -1 unreachable/timeout, -2 DNS */
}

static void
blog(const char *fmt, ...)
{
	if (!g_verbose) return;
	va_list ap;
	fputs("[wld-bore] ", stderr);
	va_start(ap, fmt); vfprintf(stderr, fmt, ap); va_end(ap);
	fputc('\n', stderr);
}

/* ---- framing (NUL-delimited) -------------------------------------------- */

typedef struct { int fd; unsigned char buf[2 * FRAME_MAX]; size_t len; } freader;

/* Read one NUL-delimited frame into out (NUL-terminated). Returns frame length,
 * 0 on clean EOF, -1 on error, -2 on recv timeout (EAGAIN). */
static int
fr_next(freader *fr, char *out, size_t cap)
{
	for (;;) {
		for (size_t i = 0; i < fr->len; i++) {
			if (fr->buf[i] == 0) {
				size_t flen = i;
				if (flen >= cap) return -1;
				memcpy(out, fr->buf, flen);
				out[flen] = '\0';
				memmove(fr->buf, fr->buf + i + 1, fr->len - i - 1);
				fr->len -= i + 1;
				return (int)flen;
			}
		}
		if (fr->len >= sizeof fr->buf) return -1; /* frame too long */
		long r = wld_sock_read(fr->fd, fr->buf + fr->len, sizeof fr->buf - fr->len);
		if (r > 0) { fr->len += (size_t)r; continue; }
		if (r == 0) return 0;
		if (wld_wouldblock()) return -2;
		if (wld_eintr()) continue;
		return -1;
	}
}

/* Send a JSON message followed by the NUL delimiter. */
static int
send_frame(int fd, const char *json)
{
	size_t n = strlen(json);
	char buf[FRAME_MAX + 1];
	if (n + 1 > sizeof buf) return -1;
	memcpy(buf, json, n);
	buf[n] = '\0'; /* delimiter */
	return wld_write_all(fd, buf, n + 1);
}

/* ---- tiny JSON field extraction (bore frames are small & well-formed) ---- */

static int
json_int(const char *s, const char *key, long *out)
{
	char pat[32];
	snprintf(pat, sizeof pat, "\"%s\"", key);
	const char *p = strstr(s, pat);
	if (!p) return -1;
	p += strlen(pat);
	while (*p && *p != ':') p++;
	if (*p != ':') return -1;
	p++;
	while (*p == ' ') p++;
	char *end;
	long v = strtol(p, &end, 10);
	if (end == p) return -1;
	*out = v;
	return 0;
}

static int
json_str(const char *s, const char *key, char *out, size_t cap)
{
	char pat[32];
	snprintf(pat, sizeof pat, "\"%s\"", key);
	const char *p = strstr(s, pat);
	if (!p) return -1;
	p += strlen(pat);
	while (*p && *p != ':') p++;
	if (*p != ':') return -1;
	p++;
	while (*p == ' ') p++;
	if (*p != '"') return -1;
	p++;
	size_t i = 0;
	while (*p && *p != '"' && i < cap - 1) out[i++] = *p++;
	out[i] = '\0';
	return (*p == '"') ? 0 : -1;
}

/* ---- per-connection proxy ----------------------------------------------- */

typedef struct {
	char   bore_host[256];
	char   bore_port[16];
	char   local_host[64];
	char   local_port[16];
	char   uuid[64];
} proxy_arg;

/* One direction of a splice: copy src->dst until EOF, then half-close dst.
 * A dedicated thread per direction avoids the head-of-line deadlock a single
 * poll loop hits when a blocking write stalls (bore uses copy_bidirectional). */
typedef struct { int src, dst; unsigned long count; } half_t;

static void *
half_pump(void *arg)
{
	half_t *h = arg;
	char buf[32768];
	for (;;) {
		long k = wld_sock_read(h->src, buf, sizeof buf);
		if (k > 0) {
			if (wld_write_all(h->dst, buf, (size_t)k) != 0) break;
			h->count += (unsigned long)k;
		} else if (k == 0) {
			break;
		} else if (!wld_eintr()) {
			break;
		}
	}
	shutdown(h->dst, SHUT_WR); /* propagate half-close */
	return NULL;
}

/* Bidirectional splice between two blocking sockets, one thread per direction. */
static void
splice2(int a, int b)
{
	half_t h1 = { a, b, 0 }, h2 = { b, a, 0 };
	pthread_t t1, t2;
	int c1 = pthread_create(&t1, NULL, half_pump, &h1);
	int c2 = pthread_create(&t2, NULL, half_pump, &h2);
	if (c1 == 0) pthread_join(t1, NULL);
	if (c2 == 0) pthread_join(t2, NULL);
	blog("proxy: closed (a->b %lu bytes, b->a %lu bytes)", h1.count, h2.count);
	wld_closesocket(a);
	wld_closesocket(b);
}

static void *
proxy_thread(void *arg)
{
	proxy_arg *pa = arg;

	int rc = connect_to(pa->bore_host, pa->bore_port, 8000);
	if (rc < 0) { blog("proxy: cannot reconnect to bore"); free(pa); return NULL; }

	char msg[FRAME_MAX];
	snprintf(msg, sizeof msg, "{\"Accept\":\"%s\"}", pa->uuid);
	if (send_frame(rc, msg) != 0) { wld_closesocket(rc); free(pa); return NULL; }

	int lc = wld_tcp_connect(pa->local_host, pa->local_port);
	if (lc < 0) { blog("proxy: cannot reach local relay"); wld_closesocket(rc); free(pa); return NULL; }

	blog("proxy: accepted %s -> %s:%s", pa->uuid, pa->local_host, pa->local_port);
	active_inc();
	splice2(rc, lc);
	active_dec();
	free(pa);
	return NULL;
}

/* ---- control connection thread ------------------------------------------ */

typedef struct {
	char bore_host[256];
	char bore_port[16];
	char local_host[64];
	char local_port[16];
	int  requested_port;
	volatile sig_atomic_t *stop;
	volatile int ready;         /* 0 pending, 1 up, -1 failed */
	volatile int assigned_port;
} bore_ctx;

static void
set_recv_timeout(int fd, int secs)
{
	struct timeval tv = { .tv_sec = secs, .tv_usec = 0 };
	setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
}

static void *
control_thread(void *arg)
{
	bore_ctx *ctx = arg;

	blog("connecting to %s:%s ...", ctx->bore_host, ctx->bore_port);
	int fd = connect_to(ctx->bore_host, ctx->bore_port, 8000);
	if (fd == -2) { blog("DNS lookup for %s failed", ctx->bore_host); ctx->ready = -1; return NULL; }
	if (fd < 0)   { blog("cannot connect to %s:%s (timeout/refused)", ctx->bore_host, ctx->bore_port); ctx->ready = -1; return NULL; }
	blog("connected to %s:%s", ctx->bore_host, ctx->bore_port);

	char hello[FRAME_MAX];
	snprintf(hello, sizeof hello, "{\"Hello\":%d}", ctx->requested_port);
	if (send_frame(fd, hello) != 0) { wld_closesocket(fd); ctx->ready = -1; return NULL; }

	freader fr = { .fd = fd, .len = 0 };
	char frame[FRAME_MAX + 1];

	/* handshake reply (3s timeout, like bore's NETWORK_TIMEOUT) */
	set_recv_timeout(fd, 3);
	int fl = fr_next(&fr, frame, sizeof frame);
	if (fl <= 0) { blog("no handshake reply from bore"); wld_closesocket(fd); ctx->ready = -1; return NULL; }

	long port;
	if (strstr(frame, "\"Challenge\"")) {
		blog("bore server requires authentication (unsupported)"); wld_closesocket(fd); ctx->ready = -1; return NULL;
	}
	if (strstr(frame, "\"Error\"")) {
		char em[128] = ""; json_str(frame, "Error", em, sizeof em);
		blog("bore error: %s", em); wld_closesocket(fd); ctx->ready = -1; return NULL;
	}
	if (strstr(frame, "\"Hello\"") == NULL || json_int(frame, "Hello", &port) != 0) {
		blog("unexpected handshake: %s", frame); wld_closesocket(fd); ctx->ready = -1; return NULL;
	}
	ctx->assigned_port = (int)port;
	ctx->ready = 1;
	blog("tunnel up: public %s:%ld", ctx->bore_host, port);

	/* main loop: 1s recv timeout so we can poll *stop */
	set_recv_timeout(fd, 1);
	while (!*(ctx->stop)) {
		int r = fr_next(&fr, frame, sizeof frame);
		if (r == -2) continue;          /* timeout: re-check stop */
		if (r <= 0) { blog("control connection closed"); break; }

		if (strstr(frame, "Heartbeat")) {
			continue;
		}
		if (strstr(frame, "\"Connection\"")) {
			char uuid[64];
			if (json_str(frame, "Connection", uuid, sizeof uuid) != 0) continue;
			proxy_arg *pa = calloc(1, sizeof *pa);
			if (pa == NULL) continue;
			snprintf(pa->bore_host, sizeof pa->bore_host, "%s", ctx->bore_host);
			snprintf(pa->bore_port, sizeof pa->bore_port, "%s", ctx->bore_port);
			snprintf(pa->local_host, sizeof pa->local_host, "%s", ctx->local_host);
			snprintf(pa->local_port, sizeof pa->local_port, "%s", ctx->local_port);
			snprintf(pa->uuid, sizeof pa->uuid, "%s", uuid);
			pthread_t t;
			if (pthread_create(&t, NULL, proxy_thread, pa) == 0)
				pthread_detach(t);
			else
				free(pa);
			continue;
		}
		if (strstr(frame, "\"Error\"")) {
			char em[128] = ""; json_str(frame, "Error", em, sizeof em);
			blog("server error: %s", em);
			continue;
		}
		/* ignore anything else (Hello/Challenge here would be stray) */
	}

	wld_closesocket(fd);
	ctx->ready = -1; /* signal the tunnel is no longer up */
	return NULL;
}

/* ---- embedded relay thread ---------------------------------------------- */

typedef struct {
	volatile sig_atomic_t *stop;
	volatile int port;    /* set once the relay has bound */
	int verbose;
} relay_ctx;

/* relay_serve fills its assigned_port early (right after bind), so the
 * orchestrator can read rc->port before the serve loop returns. */
static void *
relay_thread_live(void *arg)
{
	relay_ctx *rc = arg;
	wld_relay_serve("127.0.0.1", "0", rc->verbose, 0, rc->stop,
	                (int *)&rc->port);
	return NULL;
}

/* ---- orchestrator ------------------------------------------------------- */

int
wld_bore_autotunnel(const char *bore_host, int requested_port, int verbose,
                    char *local_port_out, size_t lpcap,
                    char *pub_host_out, size_t phcap, int *pub_port_out)
{
	g_verbose = verbose;
	if (bore_host == NULL) bore_host = WLD_BORE_DEFAULT_HOST;

	/* process-lifetime state (intentionally leaked) */
	static volatile sig_atomic_t stop; /* stays 0 */
	relay_ctx *rctx = calloc(1, sizeof *rctx);
	bore_ctx  *bctx = calloc(1, sizeof *bctx);
	if (rctx == NULL || bctx == NULL) { free(rctx); free(bctx); return -1; }
	rctx->stop = &stop;
	rctx->verbose = verbose;

	pthread_t rt;
	if (pthread_create(&rt, NULL, relay_thread_live, rctx) != 0) { blog("relay thread failed"); return -1; }
	pthread_detach(rt);

	/* wait for the embedded relay to bind (up to ~2s) */
	int relay_port = 0;
	for (int i = 0; i < 200; i++) {
		relay_port = rctx->port;
		if (relay_port > 0) break;
		struct timespec ts = { 0, 10 * 1000 * 1000 }; /* 10ms */
		nanosleep(&ts, NULL);
	}
	if (relay_port <= 0) { blog("embedded relay did not start"); return -1; }
	blog("embedded relay on 127.0.0.1:%d", relay_port);

	if (local_port_out) snprintf(local_port_out, lpcap, "%d", relay_port);

	const char *bore_port = getenv("WLD_BORE_PORT");
	if (bore_port == NULL || bore_port[0] == '\0') bore_port = WLD_BORE_CONTROL_PORT;
	snprintf(bctx->bore_host, sizeof bctx->bore_host, "%s", bore_host);
	snprintf(bctx->bore_port, sizeof bctx->bore_port, "%s", bore_port);
	snprintf(bctx->local_host, sizeof bctx->local_host, "127.0.0.1");
	snprintf(bctx->local_port, sizeof bctx->local_port, "%d", relay_port);
	bctx->requested_port = requested_port;
	bctx->stop = &stop;
	bctx->ready = 0;

	pthread_t ct;
	if (pthread_create(&ct, NULL, control_thread, bctx) != 0) { blog("bore thread failed"); return -1; }
	pthread_detach(ct);

	/* wait for the tunnel handshake (up to ~13s: 8s connect + handshake) */
	for (int i = 0; i < 1300; i++) {
		if (bctx->ready != 0) break;
		struct timespec ts = { 0, 10 * 1000 * 1000 };
		nanosleep(&ts, NULL);
	}
	if (bctx->ready != 1) return -1;

	if (pub_host_out) snprintf(pub_host_out, phcap, "%s", bore_host);
	if (pub_port_out) *pub_port_out = bctx->assigned_port;
	g_tunnel_up = 1;
	return 0;
}

void
wld_bore_drain(int max_ms)
{
	if (!g_tunnel_up) return;
	/*
	 * The relay + proxy run in background threads of THIS process; if the
	 * caller's session finishes while a proxied transfer is still in flight,
	 * exiting would truncate it. Wait until no proxy connection is active (with
	 * a short floor so a just-started transfer is observed), capped at max_ms.
	 */
	int waited = 0;
	const int step = 20;
	while (waited < max_ms) {
		if (active_get() == 0 && waited >= 300) break;
		struct timespec ts = { 0, step * 1000 * 1000 };
		nanosleep(&ts, NULL);
		waited += step;
	}
}

#endif /* POSIX */
