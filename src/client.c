/*
 * wld — the wetland client.
 *
 * Derives a rendezvous address + PSK from a shared secret, meets its peer at
 * the relay, runs the end-to-end handshake and then tunnels data. Modes:
 *   (default)   pipe stdin/stdout
 *   -e CMD      run CMD and wire its stdio to the tunnel
 *   -i          interactive PTY shell (listener serves a shell; client goes raw)
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "wld_proto.h"
#include "wld_net.h"
#include "wld_crypto.h"
#include "wld_tunnel.h"

#include "wld_compat.h"

#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifdef _WIN32
#  include <getopt.h>
#  include <io.h>
#  include <fcntl.h>
#else
#  include <errno.h>
#  include <termios.h>
#  include <unistd.h>
#  include <sys/wait.h>
#  include <sys/socket.h>
#  if defined(__APPLE__) || defined(__FreeBSD__) || defined(__NetBSD__) || defined(__OpenBSD__)
#    include <util.h>   /* forkpty on BSD/macOS */
#  else
#    include <pty.h>    /* forkpty on Linux (glibc) */
#  endif
#endif

static int g_verbose;
#define VLOG(...) do { if (g_verbose) fprintf(stderr, __VA_ARGS__); } while (0)

static void
die(const char *msg)
{
	fprintf(stderr, "wld: %s\n", msg);
	exit(1);
}

/* ---- secret generation -------------------------------------------------- */
static char *
gen_secret(void)
{
	static const char alpha[] =
	    "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789"; /* no 0/O/1/I/l */
	const int n = 20;
	char *s = malloc(n + 1);
	uint8_t rnd[64];
	if (s == NULL || wld_random(rnd, sizeof rnd) != 0)
		die("rng failure");
	for (int i = 0; i < n; i++)
		s[i] = alpha[rnd[i] % (sizeof alpha - 1)];
	s[n] = '\0';
	return s;
}

static char *
read_secret_file(const char *path)
{
	FILE *f = fopen(path, "r");
	if (f == NULL)
		die("cannot open secret file");
	char buf[512];
	if (fgets(buf, sizeof buf, f) == NULL)
		die("empty secret file");
	fclose(f);
	buf[strcspn(buf, "\r\n")] = '\0';
	if (buf[0] == '\0')
		die("empty secret");
	return strdup(buf);
}

/* ---- relay rendezvous --------------------------------------------------- */

/*
 * Connect to the relay with the given address+role, send the hello and wait
 * for START. Returns the connected tunnel fd, or -1 on error, -2 on "no server"
 * (so the caller can retry a neighbouring epoch).
 */
static int
rendezvous(const char *host, const char *port, uint8_t role, int wait_flag,
           const uint8_t addr[WLD_ADDR_LEN], const uint8_t token[WLD_TOKEN_LEN])
{
	int fd = wld_tcp_connect(host, port);
	if (fd < 0) {
		fprintf(stderr, "wld: cannot reach relay %s:%s: %s\n",
		    host, port, strerror(errno));
		return -1;
	}

	struct wld_hello h;
	memset(&h, 0, sizeof h);
	h.magic[0] = WLD_MAGIC0; h.magic[1] = WLD_MAGIC1; h.magic[2] = WLD_MAGIC2;
	h.version = WLD_PROTO_VERSION;
	h.role = role;
	h.flags = wait_flag ? WLD_HF_WAIT : 0;
	memcpy(h.addr, addr, WLD_ADDR_LEN);
	memcpy(h.token, token, WLD_TOKEN_LEN);

	if (wld_write_all(fd, &h, sizeof h) != 0) {
		wld_closesocket(fd);
		return -1;
	}

	for (;;) {
		uint8_t t;
		if (wld_read_all(fd, &t, 1) != 0) {
			wld_closesocket(fd);
			return -1;
		}
		if (t == WLD_R_WAIT) {
			VLOG("wld: registered, waiting for peer...\n");
			continue;
		}
		if (t == WLD_R_START) {
			VLOG("wld: peer matched, starting handshake\n");
			return fd;
		}
		if (t == WLD_R_ERR) {
			uint8_t code = 0;
			wld_read_all(fd, &code, 1);
			wld_closesocket(fd);
			if (code == WLD_E_NOSRV)
				return -2;
			fprintf(stderr, "wld: relay error: %s\n", wld_err_str(code));
			return -1;
		}
		/* unexpected */
		wld_closesocket(fd);
		return -1;
	}
}

/* ---- modes -------------------------------------------------------------- */

static int
mode_pipe(int tun, wld_session *sess)
{
	return wld_pump(tun, STDIN_FILENO, STDOUT_FILENO, sess);
}

#ifndef _WIN32  /* exec + PTY modes rely on fork/forkpty/termios (POSIX only) */

static int
mode_exec(int tun, wld_session *sess, const char *cmd)
{
	int sp[2];
	if (socketpair(AF_UNIX, SOCK_STREAM, 0, sp) != 0)
		return -1;

	pid_t pid = fork();
	if (pid < 0)
		return -1;
	if (pid == 0) {
		/* child: wire sp[1] to stdio and exec */
		close(sp[0]);
		dup2(sp[1], STDIN_FILENO);
		dup2(sp[1], STDOUT_FILENO);
		dup2(sp[1], STDERR_FILENO);
		if (sp[1] > STDERR_FILENO)
			close(sp[1]);
		execl("/bin/sh", "sh", "-c", cmd, (char *)NULL);
		_exit(127);
	}
	close(sp[1]);
	int rc = wld_pump(tun, sp[0], sp[0], sess);
	close(sp[0]);
	int st;
	waitpid(pid, &st, 0);
	return rc;
}

/* Listener serves an interactive login shell over a PTY. */
static int
mode_pty_server(int tun, wld_session *sess, const char *shell)
{
	int master;
	pid_t pid = forkpty(&master, NULL, NULL, NULL);
	if (pid < 0)
		return -1;
	if (pid == 0) {
		setenv("TERM", getenv("TERM") ? getenv("TERM") : "xterm-256color", 1);
		execl(shell, shell, "-i", (char *)NULL);
		execl("/bin/sh", "sh", "-i", (char *)NULL);
		_exit(127);
	}
	int rc = wld_pump(tun, master, master, sess);
	close(master);
	int st;
	waitpid(pid, &st, 0);
	return rc;
}

/* Connector drives the remote PTY: put local terminal in raw mode. */
static struct termios g_saved_tio;
static int g_tio_saved;

static void
restore_tio(void)
{
	if (g_tio_saved)
		tcsetattr(STDIN_FILENO, TCSANOW, &g_saved_tio);
}

static int
mode_pty_client(int tun, wld_session *sess)
{
	if (isatty(STDIN_FILENO)) {
		if (tcgetattr(STDIN_FILENO, &g_saved_tio) == 0) {
			g_tio_saved = 1;
			atexit(restore_tio);
			struct termios raw = g_saved_tio;
			cfmakeraw(&raw);
			tcsetattr(STDIN_FILENO, TCSANOW, &raw);
		}
	}
	int rc = wld_pump(tun, STDIN_FILENO, STDOUT_FILENO, sess);
	restore_tio();
	return rc;
}

#endif /* !_WIN32 */

/* ---- main --------------------------------------------------------------- */

static void
usage(const char *p)
{
	fprintf(stderr,
"wld — wetland client (connect like there is no firewall, securely)\n"
"\n"
"usage: %s [options]\n"
"  -s SECRET   shared secret (both peers must match)\n"
"  -k FILE     read the secret from FILE (first line)\n"
"  -g          generate a fresh secret, print it, and use it\n"
"  -l          listen mode (otherwise connect)\n"
"  -i          interactive PTY shell  (listener serves a shell)\n"
"  -e CMD      execute CMD, wire its stdio to the tunnel\n"
"  -w          (connect) wait for the listener to appear\n"
"  -R SECS     rotate the rendezvous address every SECS seconds\n"
"  -H HOST     relay host (default: $WLD_RELAY_HOST or 127.0.0.1)\n"
"  -p PORT     relay port (default: $WLD_RELAY_PORT or %s)\n"
"  -v          verbose\n"
"\n"
"examples:\n"
"  wld -g -l -i                 # serve a shell, prints the secret to share\n"
"  wld -s <secret> -i           # log into that shell from anywhere\n"
"  wld -l -e 'cat > out.bin'     # receive a file\n"
"  wld -s <secret> < in.bin      # send it\n",
	    p, WLD_RELAY_DEFAULT_PORT);
	exit(1);
}

int
main(int argc, char **argv)
{
	const char *secret = NULL, *secret_file = NULL, *cmd = NULL;
	int listen_mode = 0, interactive = 0, do_gen = 0, wait_flag = 0;
	long epoch_secs = 0;
	const char *host = getenv("WLD_RELAY_HOST");
	const char *port = getenv("WLD_RELAY_PORT");
	int opt;

	while ((opt = getopt(argc, argv, "s:k:gliwe:R:H:p:vh")) != -1) {
		switch (opt) {
		case 's': secret = optarg; break;
		case 'k': secret_file = optarg; break;
		case 'g': do_gen = 1; break;
		case 'l': listen_mode = 1; break;
		case 'i': interactive = 1; break;
		case 'w': wait_flag = 1; break;
		case 'e': cmd = optarg; break;
		case 'R': epoch_secs = atol(optarg); break;
		case 'H': host = optarg; break;
		case 'p': port = optarg; break;
		case 'v': g_verbose = 1; break;
		case 'h':
		default: usage(argv[0]);
		}
	}

	if (host == NULL) host = "127.0.0.1";
	if (port == NULL) port = WLD_RELAY_DEFAULT_PORT;

#ifndef _WIN32
	signal(SIGPIPE, SIG_IGN);
#endif
	if (wld_crypto_init() != 0)
		die("crypto init failed");
	if (wld_net_startup() != 0)
		die("network init failed");
#ifdef _WIN32
	_setmode(_fileno(stdin), _O_BINARY);
	_setmode(_fileno(stdout), _O_BINARY);
#endif

	char *gen = NULL;
	if (do_gen) {
		gen = gen_secret();
		secret = gen;
		fprintf(stderr, "wld: generated secret: %s\n", secret);
	} else if (secret_file != NULL) {
		secret = read_secret_file(secret_file);
	}
	if (secret == NULL || secret[0] == '\0')
		die("no secret given (use -s, -k or -g)");

	/* epoch for rotating addresses (0 = static) */
	uint64_t epoch0 = 0;
	if (epoch_secs > 0)
		epoch0 = (uint64_t)(time(NULL) / epoch_secs);

	uint8_t psk[WLD_PSK_LEN], addr[WLD_ADDR_LEN], token[WLD_TOKEN_LEN];
	if (wld_derive(secret, epoch0, addr, psk, token) != 0)
		die("key derivation failed");

	uint8_t role = listen_mode ? WLD_ROLE_LISTEN : WLD_ROLE_CONNECT;

	/* Rendezvous (connector may try neighbouring epochs when rotating). */
	int tun = -1;
	if (!listen_mode && epoch_secs > 0) {
		int offs[3] = { 0, -1, +1 };
		for (int i = 0; i < 3 && tun < 0; i++) {
			uint8_t a[WLD_ADDR_LEN];
			wld_derive(secret, epoch0 + offs[i], a, NULL, NULL);
			int r = rendezvous(host, port, role, wait_flag, a, token);
			if (r >= 0) { tun = r; break; }
			if (r == -1) break; /* hard error */
			VLOG("wld: no listener at epoch offset %d\n", offs[i]);
		}
		if (tun < 0)
			die("no peer is listening (try -w to wait)");
	} else {
		tun = rendezvous(host, port, role, wait_flag || listen_mode, addr, token);
		if (tun == -2)
			die("no peer is listening (try -w to wait)");
		if (tun < 0)
			exit(1);
	}

	/* End-to-end handshake. Connector = initiator, listener = responder. */
	wld_session sess;
	int hs = wld_handshake(tun, !listen_mode, psk, &sess);
	if (hs == -2)
		die("handshake failed: wrong secret or active MITM (connection refused)");
	if (hs != 0)
		die("handshake failed");
	VLOG("wld: secure channel established\n");

	wld_wipe(psk, sizeof psk);

	int rc;
#ifdef _WIN32
	if (listen_mode && (interactive || cmd != NULL)) {
		fprintf(stderr, "wld: -i/-e on the listener need a PTY; "
		    "not supported on Windows yet (use WSL)\n");
		rc = 1;
	} else {
		/* pipe mode covers file transfer and scripted I/O on Windows */
		rc = mode_pipe(tun, &sess);
	}
#else
	if (interactive) {
		if (listen_mode) {
			const char *shell = getenv("SHELL");
			rc = mode_pty_server(tun, &sess, shell ? shell : "/bin/sh");
		} else {
			rc = mode_pty_client(tun, &sess);
		}
	} else if (cmd != NULL) {
		rc = mode_exec(tun, &sess, cmd);
	} else {
		rc = mode_pipe(tun, &sess);
	}
#endif

	wld_closesocket(tun);
	free(gen);
	return rc == 0 ? 0 : 1;
}
