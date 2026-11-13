/*
 * wetland-relay — the rendezvous server.
 *
 * Pairs a CONNECT with a waiting LISTEN that share the same 16-byte address,
 * then splices their TCP streams. It only ever sees the rendezvous address and
 * ciphertext; the end-to-end key never reaches it.
 *
 * Single-threaded, poll(2) based, handles many concurrent pairs.
 */
#include "wld_proto.h"
#include "wld_net.h"
#include "wld_crypto.h"
#include "wld_compat.h"

#include <errno.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#ifdef _WIN32
#  include <getopt.h>
#endif

#define RELAY_OUTBUF   (128 * 1024)
#define MAX_CONNS      8192

enum conn_state {
	ST_FREE = 0,
	ST_HELLO,         /* reading the 48-byte hello            */
	ST_WAIT_LISTEN,   /* listener registered, awaiting peer   */
	ST_WAIT_CONNECT,  /* connector waiting for a listener     */
	ST_PAIRED,        /* spliced to peer_fd                   */
	ST_DRAIN,         /* flush out buffer then close          */
};

typedef struct {
	int   fd;
	int   state;
	uint8_t role;
	uint8_t addr[WLD_ADDR_LEN];
	uint8_t token[WLD_TOKEN_LEN];

	uint8_t  hbuf[WLD_HELLO_LEN];
	size_t   hlen;

	int      peer_fd;     /* ST_PAIRED: the other end         */
	int      rd_eof;      /* our read side saw EOF            */
	int      wr_shut;     /* we've half-closed our write side */

	/* linear output buffer */
	uint8_t *out;
	size_t   ocap, ooff, olen;
} conn_t;

static conn_t *g_conns;      /* indexed by fd */
static int     g_cap;        /* allocated slots */
static int     g_verbose;
static volatile sig_atomic_t g_stop;

static void on_sig(int s) { (void)s; g_stop = 1; }

static void
logv(const char *fmt, ...)
{
	if (!g_verbose)
		return;
	char ts[32];
	time_t t = time(NULL);
	strftime(ts, sizeof ts, "%H:%M:%S", localtime(&t));
	fprintf(stderr, "[%s] ", ts);
	va_list ap; va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
	fputc('\n', stderr);
}

static conn_t *
conn_get(int fd)
{
	if (fd < 0 || fd >= g_cap)
		return NULL;
	return &g_conns[fd];
}

/* queue bytes to a conn's output buffer */
static int
conn_queue(conn_t *c, const void *data, size_t n)
{
	if (c->out == NULL) {
		c->out = malloc(RELAY_OUTBUF);
		if (c->out == NULL)
			return -1;
		c->ocap = RELAY_OUTBUF;
	}
	/* compact */
	if (c->ooff + c->olen + n > c->ocap) {
		if (c->olen > 0)
			memmove(c->out, c->out + c->ooff, c->olen);
		c->ooff = 0;
	}
	if (c->olen + n > c->ocap)
		return -1; /* overflow */
	memcpy(c->out + c->ooff + c->olen, data, n);
	c->olen += n;
	return 0;
}

static void
conn_close(conn_t *c)
{
	if (c->fd >= 0)
		wld_closesocket(c->fd);
	free(c->out);
	int fd = c->fd;
	memset(c, 0, sizeof *c);
	c->fd = -1;
	(void)fd;
}

/* Send R_ERR then schedule close. */
static void
send_err(conn_t *c, uint8_t code)
{
	uint8_t msg[2] = { WLD_R_ERR, code };
	conn_queue(c, msg, sizeof msg);
	c->state = ST_DRAIN;
}

static void
tear_down_pair(conn_t *c)
{
	conn_t *p = conn_get(c->peer_fd);
	conn_close(c);
	if (p != NULL && p->state == ST_PAIRED) {
		p->state = ST_DRAIN; /* let its output flush, then close */
		p->peer_fd = -1;
	}
}

/* Find a waiting listener for addr. */
static conn_t *
find_listener(const uint8_t addr[WLD_ADDR_LEN])
{
	for (int fd = 0; fd < g_cap; fd++) {
		conn_t *c = &g_conns[fd];
		if (c->state == ST_WAIT_LISTEN &&
		    memcmp(c->addr, addr, WLD_ADDR_LEN) == 0)
			return c;
	}
	return NULL;
}

static conn_t *
find_waiting_connector(const uint8_t addr[WLD_ADDR_LEN])
{
	for (int fd = 0; fd < g_cap; fd++) {
		conn_t *c = &g_conns[fd];
		if (c->state == ST_WAIT_CONNECT &&
		    memcmp(c->addr, addr, WLD_ADDR_LEN) == 0)
			return c;
	}
	return NULL;
}

static void
pair_up(conn_t *a, conn_t *b)
{
	uint8_t start = WLD_R_START;
	conn_queue(a, &start, 1);
	conn_queue(b, &start, 1);
	a->state = b->state = ST_PAIRED;
	a->peer_fd = b->fd;
	b->peer_fd = a->fd;
	logv("paired fd=%d <-> fd=%d", a->fd, b->fd);
}

/* Process a fully-received hello. */
static void
handle_hello(conn_t *c)
{
	struct wld_hello h;
	memcpy(&h, c->hbuf, sizeof h);

	if (h.magic[0] != WLD_MAGIC0 || h.magic[1] != WLD_MAGIC1 ||
	    h.magic[2] != WLD_MAGIC2 || h.version != WLD_PROTO_VERSION) {
		send_err(c, WLD_E_PROTO);
		return;
	}
	c->role = h.role;
	memcpy(c->addr, h.addr, WLD_ADDR_LEN);
	memcpy(c->token, h.token, WLD_TOKEN_LEN);

	if (h.role == WLD_ROLE_LISTEN) {
		conn_t *dup = find_listener(c->addr);
		if (dup != NULL) {
			logv("fd=%d listen rejected: addr in use by fd=%d", c->fd, dup->fd);
			send_err(c, WLD_E_INUSE);
			return;
		}
		conn_t *waiter = find_waiting_connector(c->addr);
		if (waiter != NULL) {
			pair_up(c, waiter);
		} else {
			uint8_t w = WLD_R_WAIT;
			conn_queue(c, &w, 1);
			c->state = ST_WAIT_LISTEN;
			logv("fd=%d listening", c->fd);
		}
	} else if (h.role == WLD_ROLE_CONNECT) {
		conn_t *lis = find_listener(c->addr);
		if (lis != NULL) {
			pair_up(lis, c);
		} else if (h.flags & WLD_HF_WAIT) {
			uint8_t w = WLD_R_WAIT;
			conn_queue(c, &w, 1);
			c->state = ST_WAIT_CONNECT;
			logv("fd=%d connector waiting (no listener yet)", c->fd);
		} else {
			send_err(c, WLD_E_NOSRV);
		}
	} else {
		send_err(c, WLD_E_PROTO);
	}
}

static void
accept_new(int lfd)
{
	for (;;) {
		int fd = (int)accept((SOCKET_CAST)lfd, NULL, NULL);
		if (fd < 0) {
			if (wld_eintr())
				continue;
			return; /* would-block or real error: stop accepting for now */
		}
		if (fd >= g_cap || fd >= MAX_CONNS) {
			wld_closesocket(fd);
			continue;
		}
		conn_t *c = &g_conns[fd];
		memset(c, 0, sizeof *c);
		c->fd = fd;
		c->state = ST_HELLO;
		c->peer_fd = -1;
		wld_set_nonblock(fd, 1);
		wld_set_keepalive(fd);
	}
}

/* Read from a HELLO-state conn. */
static void
do_hello_read(conn_t *c)
{
	long r = wld_sock_read(c->fd, c->hbuf + c->hlen, WLD_HELLO_LEN - c->hlen);
	if (r > 0) {
		c->hlen += (size_t)r;
		if (c->hlen == WLD_HELLO_LEN)
			handle_hello(c);
	} else if (r == 0) {
		conn_close(c);
	} else if (!wld_wouldblock() && !wld_eintr()) {
		conn_close(c);
	}
}

/* Paired: read from c and queue into peer's out buffer. */
static void
do_paired_read(conn_t *c)
{
	conn_t *p = conn_get(c->peer_fd);
	if (p == NULL) {
		c->state = ST_DRAIN;
		return;
	}
	uint8_t tmp[65536];
	size_t room = p->ocap ? (p->ocap - p->olen) : RELAY_OUTBUF;
	if (room > sizeof tmp)
		room = sizeof tmp;
	if (room == 0)
		return; /* backpressure */
	long r = wld_sock_read(c->fd, tmp, room);
	if (r > 0) {
		if (conn_queue(p, tmp, (size_t)r) != 0) {
			logv("OVERFLOW fd=%d -> peer fd=%d, tearing down", c->fd, p->fd);
			tear_down_pair(c);
		}
	} else if (r == 0) {
		c->rd_eof = 1; /* half-close: propagate once peer out drained */
	} else if (!wld_wouldblock() && !wld_eintr()) {
		tear_down_pair(c);
	}
}

static void
do_write(conn_t *c)
{
	if (c->olen == 0)
		return;
	long w = wld_sock_write(c->fd, c->out + c->ooff, c->olen);
	if (w > 0) {
		c->ooff += (size_t)w;
		c->olen -= (size_t)w;
		if (c->olen == 0)
			c->ooff = 0;
	} else if (w < 0 && !wld_wouldblock() && !wld_eintr()) {
		if (c->state == ST_PAIRED)
			tear_down_pair(c);
		else
			conn_close(c);
	}
}

int
main(int argc, char **argv)
{
	const char *host = NULL;
	const char *port = WLD_RELAY_DEFAULT_PORT;
	int opt;

	while ((opt = getopt(argc, argv, "b:p:vh")) != -1) {
		switch (opt) {
		case 'b': host = optarg; break;
		case 'p': port = optarg; break;
		case 'v': g_verbose = 1; break;
		case 'h':
		default:
			fprintf(stderr,
			    "wetland-relay — rendezvous server\n"
			    "usage: %s [-b bind-addr] [-p port] [-v]\n"
			    "  -b ADDR   bind address (default: all interfaces)\n"
			    "  -p PORT   listen port (default: %s)\n"
			    "  -v        verbose logging\n", argv[0], WLD_RELAY_DEFAULT_PORT);
			return opt == 'h' ? 0 : 1;
		}
	}

#ifndef _WIN32
	signal(SIGPIPE, SIG_IGN);
#endif
	signal(SIGINT, on_sig);
	signal(SIGTERM, on_sig);

	if (wld_crypto_init() != 0) {
		fprintf(stderr, "crypto init failed\n");
		return 1;
	}
	if (wld_net_startup() != 0) {
		fprintf(stderr, "network init failed\n");
		return 1;
	}

	int lfd = wld_tcp_listen(host, port, 128);
	if (lfd < 0) {
		fprintf(stderr, "cannot listen on %s:%s: %s\n",
		    host ? host : "*", port, strerror(errno));
		return 1;
	}
	wld_set_nonblock(lfd, 1);

	g_cap = MAX_CONNS;
	g_conns = calloc(g_cap, sizeof *g_conns);
	if (g_conns == NULL) {
		fprintf(stderr, "out of memory\n");
		return 1;
	}
	for (int i = 0; i < g_cap; i++)
		g_conns[i].fd = -1;

	fprintf(stderr, "wetland-relay listening on %s:%s\n", host ? host : "*", port);

	wld_pollfd *pfds = calloc(g_cap + 1, sizeof *pfds);
	if (pfds == NULL)
		return 1;

	while (!g_stop) {
		int n = 0;
		pfds[n].fd = lfd; pfds[n].events = POLLIN; n++;

		for (int fd = 0; fd < g_cap; fd++) {
			conn_t *c = &g_conns[fd];
			if (c->fd < 0)
				continue;
			short ev = 0;
			switch (c->state) {
			case ST_HELLO:
				ev |= POLLIN;
				break;
			case ST_WAIT_LISTEN:
			case ST_WAIT_CONNECT:
				ev |= POLLIN; /* detect disconnect */
				if (c->olen > 0) ev |= POLLOUT;
				break;
			case ST_PAIRED: {
				conn_t *p = conn_get(c->peer_fd);
				int peer_room = (p && p->ocap) ? (int)(p->ocap - p->olen) : RELAY_OUTBUF;
				if (!c->rd_eof && peer_room > 0)
					ev |= POLLIN;
				if (c->olen > 0)
					ev |= POLLOUT;
				break;
			}
			case ST_DRAIN:
				if (c->olen > 0) ev |= POLLOUT;
				break;
			}
			if (ev == 0 && c->state == ST_DRAIN) {
				conn_close(c);
				continue;
			}
			pfds[n].fd = c->fd;
			pfds[n].events = ev;
			n++;
		}

		int pr = wld_poll(pfds, n, 1000);
		if (pr < 0) {
			if (errno == EINTR)
				continue;
			break;
		}

		for (int i = 0; i < n; i++) {
			if (pfds[i].revents == 0)
				continue;
			if (pfds[i].fd == lfd) {
				accept_new(lfd);
				continue;
			}
			conn_t *c = conn_get(pfds[i].fd);
			if (c == NULL || c->fd < 0)
				continue;

			if (pfds[i].revents & POLLOUT)
				do_write(c);
			if (c->fd < 0)
				continue;

			if (pfds[i].revents & (POLLIN | POLLHUP)) {
				switch (c->state) {
				case ST_HELLO:  do_hello_read(c);  break;
				case ST_PAIRED: do_paired_read(c); break;
				case ST_WAIT_LISTEN:
				case ST_WAIT_CONNECT: {
					/* any readable event here means peer closed */
					uint8_t b;
					long r = recv((SOCKET_CAST)c->fd, (char *)&b, 1, MSG_PEEK);
					if (r <= 0 && !(r < 0 && (wld_wouldblock() || wld_eintr())))
						conn_close(c);
					break;
				}
				default: break;
				}
			}
		}

		/* Post-pass: propagate half-close and tear down finished pairs.
		 *
		 * Data read from a conn is queued into its peer's output buffer, so
		 * "all of c's data delivered to p" is exactly "p->olen == 0". We only
		 * propagate c's EOF (FIN) to p once that holds, and only close the pair
		 * once BOTH directions are EOF and BOTH output buffers are empty — so
		 * no in-flight bytes are ever discarded. */
		for (int fd = 0; fd < g_cap; fd++) {
			conn_t *c = &g_conns[fd];
			if (c->fd < 0)
				continue;
			if (c->state == ST_DRAIN) {
				if (c->olen == 0)
					conn_close(c);
				continue;
			}
			if (c->state != ST_PAIRED)
				continue;

			conn_t *p = conn_get(c->peer_fd);
			if (p == NULL || p->fd < 0) {
				if (c->olen == 0)
					conn_close(c);
				else
					c->state = ST_DRAIN;
				continue;
			}

			/* c finished sending and all of it reached p -> half-close p */
			if (c->rd_eof && p->olen == 0 && !p->wr_shut) {
				shutdown((SOCKET_CAST)p->fd, SHUT_WR);
				p->wr_shut = 1;
			}

			/* both ends done and both buffers drained -> close the pair */
			if (c->rd_eof && p->rd_eof && c->olen == 0 && p->olen == 0) {
				conn_close(c);
				conn_close(p);
			}
		}
	}

	fprintf(stderr, "\nwetland-relay shutting down\n");
	free(pfds);
	free(g_conns);
	wld_closesocket(lfd);
	return 0;
}
