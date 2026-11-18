/*
 * wetland — native frp reverse-tunnel client (see wld_frp.h).
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "wld_frp.h"
#include "wld_relay.h"
#include "wld_net.h"
#include "wld_compat.h"

#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32

int
wld_frp_autotunnel(const char *server_host, const char *server_port,
                   const char *token, int remote_port, int verbose,
                   char *local_port_out, size_t lpcap,
                   char *pub_host_out, size_t phcap, int *pub_port_out)
{
	(void)server_host; (void)server_port; (void)token; (void)remote_port;
	(void)verbose; (void)local_port_out; (void)lpcap; (void)pub_host_out;
	(void)phcap; (void)pub_port_out;
	return -1; /* frp tunnel is POSIX-only */
}

void wld_frp_drain(int max_ms) { (void)max_ms; }

#else /* ---------------------------------------------------------------- POSIX */

#include <pthread.h>
#include <stdarg.h>
#include <stdint.h>
#include <time.h>
#include <sys/socket.h>
#include <sys/time.h>

#define FRP_MSGBUF 16384

/* frp message type bytes */
#define T_LOGIN         'o'
#define T_LOGIN_RESP    '1'
#define T_NEWPROXY      'p'
#define T_NEWPROXY_RESP '2'
#define T_NEWWORKCONN   'w'
#define T_REQWORKCONN   'r'
#define T_STARTWORKCONN 's'
#define T_PING          'h'
#define T_PONG          '4'

static int g_verbose;
static int g_tunnel_up;
static pthread_mutex_t g_amx = PTHREAD_MUTEX_INITIALIZER;
static int g_active;

static void active_inc(void) { pthread_mutex_lock(&g_amx); g_active++; pthread_mutex_unlock(&g_amx); }
static void active_dec(void) { pthread_mutex_lock(&g_amx); g_active--; pthread_mutex_unlock(&g_amx); }
static int  active_get(void) { pthread_mutex_lock(&g_amx); int v = g_active; pthread_mutex_unlock(&g_amx); return v; }

static void
flog(const char *fmt, ...)
{
	if (!g_verbose) return;
	va_list ap;
	fputs("[wld-frp] ", stderr);
	va_start(ap, fmt); vfprintf(stderr, fmt, ap); va_end(ap);
	fputc('\n', stderr);
}

/* ---- MD5 (RFC 1321, public-domain style) -------------------------------- */

typedef struct { uint32_t a, b, c, d; uint64_t len; unsigned char buf[64]; size_t n; } md5_ctx;

static uint32_t md5_rol(uint32_t x, int c) { return (x << c) | (x >> (32 - c)); }

static void
md5_block(md5_ctx *m, const unsigned char *p)
{
	static const uint32_t K[64] = {
		0xd76aa478,0xe8c7b756,0x242070db,0xc1bdceee,0xf57c0faf,0x4787c62a,0xa8304613,0xfd469501,
		0x698098d8,0x8b44f7af,0xffff5bb1,0x895cd7be,0x6b901122,0xfd987193,0xa679438e,0x49b40821,
		0xf61e2562,0xc040b340,0x265e5a51,0xe9b6c7aa,0xd62f105d,0x02441453,0xd8a1e681,0xe7d3fbc8,
		0x21e1cde6,0xc33707d6,0xf4d50d87,0x455a14ed,0xa9e3e905,0xfcefa3f8,0x676f02d9,0x8d2a4c8a,
		0xfffa3942,0x8771f681,0x6d9d6122,0xfde5380c,0xa4beea44,0x4bdecfa9,0xf6bb4b60,0xbebfbc70,
		0x289b7ec6,0xeaa127fa,0xd4ef3085,0x04881d05,0xd9d4d039,0xe6db99e5,0x1fa27cf8,0xc4ac5665,
		0xf4292244,0x432aff97,0xab9423a7,0xfc93a039,0x655b59c3,0x8f0ccc92,0xffeff47d,0x85845dd1,
		0x6fa87e4f,0xfe2ce6e0,0xa3014314,0x4e0811a1,0xf7537e82,0xbd3af235,0x2ad7d2bb,0xeb86d391 };
	static const int S[64] = {
		7,12,17,22,7,12,17,22,7,12,17,22,7,12,17,22,
		5,9,14,20,5,9,14,20,5,9,14,20,5,9,14,20,
		4,11,16,23,4,11,16,23,4,11,16,23,4,11,16,23,
		6,10,15,21,6,10,15,21,6,10,15,21,6,10,15,21 };
	uint32_t M[16];
	for (int i = 0; i < 16; i++)
		M[i] = (uint32_t)p[i*4] | ((uint32_t)p[i*4+1] << 8) |
		       ((uint32_t)p[i*4+2] << 16) | ((uint32_t)p[i*4+3] << 24);
	uint32_t A = m->a, B = m->b, C = m->c, D = m->d;
	for (int i = 0; i < 64; i++) {
		uint32_t F; int g;
		if (i < 16)      { F = (B & C) | (~B & D);      g = i; }
		else if (i < 32) { F = (D & B) | (~D & C);      g = (5*i + 1) & 15; }
		else if (i < 48) { F = B ^ C ^ D;               g = (3*i + 5) & 15; }
		else             { F = C ^ (B | ~D);            g = (7*i) & 15; }
		F = F + A + K[i] + M[g];
		A = D; D = C; C = B; B = B + md5_rol(F, S[i]);
	}
	m->a += A; m->b += B; m->c += C; m->d += D;
}

static void
md5_hex(const char *data, char out[33])
{
	md5_ctx m = { 0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0, {0}, 0 };
	size_t len = strlen(data);
	m.len = len;
	const unsigned char *p = (const unsigned char *)data;
	while (len >= 64) { md5_block(&m, p); p += 64; len -= 64; }
	unsigned char tail[128];
	memcpy(tail, p, len);
	tail[len] = 0x80;
	size_t pad = (len < 56) ? (56 - len) : (120 - len);
	memset(tail + len + 1, 0, pad - 1);
	uint64_t bits = m.len * 8;
	for (int i = 0; i < 8; i++) tail[len + pad + i] = (unsigned char)(bits >> (8*i));
	size_t total = len + pad + 8;
	for (size_t off = 0; off < total; off += 64) md5_block(&m, tail + off);
	uint32_t v[4] = { m.a, m.b, m.c, m.d };
	static const char hx[] = "0123456789abcdef";
	for (int i = 0; i < 4; i++)
		for (int j = 0; j < 4; j++) {
			unsigned char byte = (unsigned char)(v[i] >> (8*j));
			out[(i*4+j)*2]   = hx[byte >> 4];
			out[(i*4+j)*2+1] = hx[byte & 15];
		}
	out[32] = '\0';
}

/* ---- frp framing: [type][int64 BE length][json] ------------------------- */

static int
frp_write(int fd, char type, const char *json)
{
	size_t n = strlen(json);
	unsigned char hdr[9];
	hdr[0] = (unsigned char)type;
	uint64_t L = n;
	for (int i = 8; i >= 1; i--) { hdr[i] = (unsigned char)(L & 0xff); L >>= 8; }
	if (wld_write_all(fd, hdr, 9) != 0) return -1;
	if (n > 0 && wld_write_all(fd, json, n) != 0) return -1;
	return 0;
}

/* read one message; returns 0 ok, -1 error/eof */
static int
frp_read(int fd, char *type, char *buf, size_t cap)
{
	unsigned char hdr[9];
	if (wld_read_all(fd, hdr, 9) != 0) return -1;
	*type = (char)hdr[0];
	uint64_t L = 0;
	for (int i = 1; i < 9; i++) L = (L << 8) | hdr[i];
	if (L > cap - 1) return -1;
	if (L > 0 && wld_read_all(fd, buf, (size_t)L) != 0) return -1;
	buf[L] = '\0';
	return 0;
}

/* read with a readability poll first; -2 = timeout, -1 = error, 0 = ok */
static int
frp_read_to(int fd, char *type, char *buf, size_t cap, int ms)
{
	wld_pollfd p; p.fd = fd; p.events = POLLIN;
	int r = wld_poll(&p, 1, ms);
	if (r == 0) return -2;
	if (r < 0) return wld_eintr() ? -2 : -1;
	return frp_read(fd, type, buf, cap);
}

/* ---- tiny JSON field extraction ----------------------------------------- */

static int
json_str(const char *s, const char *key, char *out, size_t cap)
{
	char pat[48];
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
	while (*p && *p != '"' && i < cap - 1) {
		if (*p == '\\' && p[1]) p++;
		out[i++] = *p++;
	}
	out[i] = '\0';
	return (*p == '"') ? 0 : -1;
}

/* ---- bidirectional splice (one thread per direction) -------------------- */

typedef struct { int src, dst; } half_t;

static void *
half_pump(void *arg)
{
	half_t *h = arg;
	char buf[32768];
	for (;;) {
		long k = wld_sock_read(h->src, buf, sizeof buf);
		if (k > 0) { if (wld_write_all(h->dst, buf, (size_t)k) != 0) break; }
		else if (k == 0) break;
		else if (!wld_eintr()) break;
	}
	shutdown(h->dst, SHUT_WR);
	return NULL;
}

static void
splice2(int a, int b)
{
	half_t h1 = { a, b }, h2 = { b, a };
	pthread_t t1, t2;
	int c1 = pthread_create(&t1, NULL, half_pump, &h1);
	int c2 = pthread_create(&t2, NULL, half_pump, &h2);
	if (c1 == 0) pthread_join(t1, NULL);
	if (c2 == 0) pthread_join(t2, NULL);
	wld_closesocket(a);
	wld_closesocket(b);
}

/* ---- per-connection work proxy ------------------------------------------ */

typedef struct {
	char server_host[256];
	char server_port[16];
	char run_id[128];
	char local_host[64];
	char local_port[16];
} work_arg;

static void *
work_thread(void *arg)
{
	work_arg *wa = arg;

	int fd = wld_tcp_connect(wa->server_host, wa->server_port);
	if (fd < 0) { flog("work: reconnect to frps failed"); free(wa); return NULL; }

	char msg[512];
	snprintf(msg, sizeof msg, "{\"run_id\":\"%s\"}", wa->run_id);
	if (frp_write(fd, T_NEWWORKCONN, msg) != 0) { wld_closesocket(fd); free(wa); return NULL; }

	/* server replies StartWorkConn, then the connection carries raw bytes */
	char type; char buf[FRP_MSGBUF];
	if (frp_read_to(fd, &type, buf, sizeof buf, 5000) != 0 || type != T_STARTWORKCONN) {
		flog("work: no StartWorkConn"); wld_closesocket(fd); free(wa); return NULL;
	}
	char err[256] = "";
	if (json_str(buf, "error", err, sizeof err) == 0 && err[0] != '\0') {
		flog("work: start error: %s", err); wld_closesocket(fd); free(wa); return NULL;
	}

	int lc = wld_tcp_connect(wa->local_host, wa->local_port);
	if (lc < 0) { flog("work: local relay unreachable"); wld_closesocket(fd); free(wa); return NULL; }

	flog("work: proxying -> %s:%s", wa->local_host, wa->local_port);
	active_inc();
	splice2(fd, lc);
	active_dec();
	free(wa);
	return NULL;
}

/* ---- control connection ------------------------------------------------- */

typedef struct {
	char server_host[256];
	char server_port[16];
	char token[256];
	char local_host[64];
	char local_port[16];
	int  remote_port;
	volatile sig_atomic_t *stop;
	volatile int ready;         /* 0 pending, 1 up, -1 failed */
	volatile int assigned_port;
} frp_ctx;

static void *
control_thread(void *arg)
{
	frp_ctx *ctx = arg;
	char buf[FRP_MSGBUF];
	char type;

	int fd = wld_tcp_connect(ctx->server_host, ctx->server_port);
	if (fd < 0) { flog("cannot connect to frps %s:%s", ctx->server_host, ctx->server_port); ctx->ready = -1; return NULL; }

	/* Login */
	long ts = (long)time(NULL);
	char keysrc[320], key[33];
	snprintf(keysrc, sizeof keysrc, "%s%ld", ctx->token, ts);
	md5_hex(keysrc, key);
	char login[512];
	snprintf(login, sizeof login,
	    "{\"version\":\"0.58.1\",\"hostname\":\"wetland\",\"os\":\"linux\","
	    "\"arch\":\"amd64\",\"privilege_key\":\"%s\",\"timestamp\":%ld,"
	    "\"pool_count\":0}", key, ts);
	if (frp_write(fd, T_LOGIN, login) != 0) { flog("login send failed"); wld_closesocket(fd); ctx->ready = -1; return NULL; }

	if (frp_read_to(fd, &type, buf, sizeof buf, 5000) != 0 || type != T_LOGIN_RESP) {
		flog("no LoginResp from frps"); wld_closesocket(fd); ctx->ready = -1; return NULL;
	}
	char err[256] = "";
	if (json_str(buf, "error", err, sizeof err) == 0 && err[0] != '\0') {
		flog("frps login error: %s", err); wld_closesocket(fd); ctx->ready = -1; return NULL;
	}
	char run_id[128] = "";
	json_str(buf, "run_id", run_id, sizeof run_id);
	flog("logged in (run_id=%s)", run_id);

	/* NewProxy (tcp) */
	char np[512];
	snprintf(np, sizeof np,
	    "{\"proxy_name\":\"wld-%ld\",\"proxy_type\":\"tcp\",\"remote_port\":%d}",
	    ts, ctx->remote_port);
	if (frp_write(fd, T_NEWPROXY, np) != 0) { flog("newproxy send failed"); wld_closesocket(fd); ctx->ready = -1; return NULL; }

	if (frp_read_to(fd, &type, buf, sizeof buf, 5000) != 0 || type != T_NEWPROXY_RESP) {
		flog("no NewProxyResp from frps"); wld_closesocket(fd); ctx->ready = -1; return NULL;
	}
	err[0] = '\0';
	if (json_str(buf, "error", err, sizeof err) == 0 && err[0] != '\0') {
		flog("frps proxy error: %s", err); wld_closesocket(fd); ctx->ready = -1; return NULL;
	}
	int assigned = ctx->remote_port;
	char raddr[128] = "";
	if (json_str(buf, "remote_addr", raddr, sizeof raddr) == 0) {
		char *c = strrchr(raddr, ':');
		if (c && c[1]) assigned = atoi(c + 1);
	}
	ctx->assigned_port = assigned;
	ctx->ready = 1;
	flog("tunnel up: %s:%d", ctx->server_host, assigned);

	/* control loop: handle ReqWorkConn, send periodic Ping */
	time_t last_ping = time(NULL);
	while (!*(ctx->stop)) {
		int r = frp_read_to(fd, &type, buf, sizeof buf, 1000);
		if (r == -2) {
			if (time(NULL) - last_ping >= 25) {
				if (frp_write(fd, T_PING, "{}") != 0) { flog("ping failed"); break; }
				last_ping = time(NULL);
			}
			continue;
		}
		if (r != 0) { flog("control connection closed"); break; }

		if (type == T_REQWORKCONN) {
			work_arg *wa = calloc(1, sizeof *wa);
			if (wa == NULL) continue;
			snprintf(wa->server_host, sizeof wa->server_host, "%s", ctx->server_host);
			snprintf(wa->server_port, sizeof wa->server_port, "%s", ctx->server_port);
			snprintf(wa->run_id, sizeof wa->run_id, "%s", run_id);
			snprintf(wa->local_host, sizeof wa->local_host, "%s", ctx->local_host);
			snprintf(wa->local_port, sizeof wa->local_port, "%s", ctx->local_port);
			pthread_t t;
			if (pthread_create(&t, NULL, work_thread, wa) == 0) pthread_detach(t);
			else free(wa);
		} else if (type == T_PONG) {
			/* keepalive ack */
		} else if (type == T_PING) {
			frp_write(fd, T_PONG, "{}");
		}
		/* ignore other control messages */
	}

	wld_closesocket(fd);
	ctx->ready = -1;
	return NULL;
}

/* ---- embedded relay thread ---------------------------------------------- */

typedef struct { volatile sig_atomic_t *stop; volatile int port; int verbose; } relay_ctx;

static void *
relay_thread_live(void *arg)
{
	relay_ctx *rc = arg;
	wld_relay_serve("127.0.0.1", "0", rc->verbose, 0, rc->stop, (int *)&rc->port);
	return NULL;
}

/* ---- orchestrator ------------------------------------------------------- */

int
wld_frp_autotunnel(const char *server_host, const char *server_port,
                   const char *token, int remote_port, int verbose,
                   char *local_port_out, size_t lpcap,
                   char *pub_host_out, size_t phcap, int *pub_port_out)
{
	g_verbose = verbose;
	if (server_host == NULL || server_host[0] == '\0') { flog("no frps host (set WLD_FRP_SERVER)"); return -1; }
	if (server_port == NULL || server_port[0] == '\0') server_port = WLD_FRP_DEFAULT_PORT;
	if (token == NULL) token = "";

	static volatile sig_atomic_t stop;
	relay_ctx *rctx = calloc(1, sizeof *rctx);
	frp_ctx   *fctx = calloc(1, sizeof *fctx);
	if (rctx == NULL || fctx == NULL) { free(rctx); free(fctx); return -1; }
	rctx->stop = &stop;
	rctx->verbose = verbose;

	pthread_t rt;
	if (pthread_create(&rt, NULL, relay_thread_live, rctx) != 0) { flog("relay thread failed"); return -1; }
	pthread_detach(rt);

	int relay_port = 0;
	for (int i = 0; i < 200; i++) {
		relay_port = rctx->port;
		if (relay_port > 0) break;
		struct timespec tsp = { 0, 10 * 1000 * 1000 };
		nanosleep(&tsp, NULL);
	}
	if (relay_port <= 0) { flog("embedded relay did not start"); return -1; }
	flog("embedded relay on 127.0.0.1:%d", relay_port);
	if (local_port_out) snprintf(local_port_out, lpcap, "%d", relay_port);

	snprintf(fctx->server_host, sizeof fctx->server_host, "%s", server_host);
	snprintf(fctx->server_port, sizeof fctx->server_port, "%s", server_port);
	snprintf(fctx->token, sizeof fctx->token, "%s", token);
	snprintf(fctx->local_host, sizeof fctx->local_host, "127.0.0.1");
	snprintf(fctx->local_port, sizeof fctx->local_port, "%d", relay_port);
	fctx->remote_port = remote_port;
	fctx->stop = &stop;
	fctx->ready = 0;

	pthread_t ct;
	if (pthread_create(&ct, NULL, control_thread, fctx) != 0) { flog("control thread failed"); return -1; }
	pthread_detach(ct);

	for (int i = 0; i < 600; i++) {
		if (fctx->ready != 0) break;
		struct timespec tsp = { 0, 10 * 1000 * 1000 };
		nanosleep(&tsp, NULL);
	}
	if (fctx->ready != 1) return -1;

	if (pub_host_out) snprintf(pub_host_out, phcap, "%s", server_host);
	if (pub_port_out) *pub_port_out = fctx->assigned_port;
	g_tunnel_up = 1;
	return 0;
}

void
wld_frp_drain(int max_ms)
{
	if (!g_tunnel_up) return;
	int waited = 0;
	const int step = 20;
	while (waited < max_ms) {
		if (active_get() == 0 && waited >= 300) break;
		struct timespec tsp = { 0, step * 1000 * 1000 };
		nanosleep(&tsp, NULL);
		waited += step;
	}
}

#endif /* POSIX */
