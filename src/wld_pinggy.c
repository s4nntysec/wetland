/*
 * wetland — pinggy reverse-tunnel backend (see wld_pinggy.h).
 *
 * Brings up the in-process embedded relay on a loopback port, then opens a
 * public TCP reverse tunnel to it through pinggy over ssh, and reports the
 * assigned public host:port. POSIX uses pthreads + fork/exec; Windows uses
 * Win32 threads + CreateProcess(ssh.exe) (OpenSSH, shipped with Windows 10+),
 * with a Job Object so the ssh child dies if this process does.
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "wld_pinggy.h"
#include "wld_relay.h"
#include "wld_compat.h"

#include <ctype.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define PINGGY_HOST "a.pinggy.io"

static int g_verbose;

static void
plog(const char *fmt, ...)
{
	if (!g_verbose) return;
	va_list ap;
	fputs("[wld-pinggy] ", stderr);
	va_start(ap, fmt); vfprintf(stderr, fmt, ap); va_end(ap);
	fputc('\n', stderr);
}

/* Parse pinggy's assigned "tcp://host:port" out of ssh's output. */
static int
parse_tcp_url(const char *s, char *host, size_t hostcap, int *port)
{
	const char *p = strstr(s, "tcp://");
	if (p == NULL) return -1;
	p += 6;
	size_t i = 0;
	while (*p && (isalnum((unsigned char)*p) || *p == '.' || *p == '-') && i < hostcap - 1)
		host[i++] = *p++;
	host[i] = '\0';
	if (*p != ':' || i == 0) return -1;
	p++;
	int pt = atoi(p);
	if (pt <= 0 || pt > 65535) return -1;
	*port = pt;
	return 0;
}

#ifdef _WIN32  /* ===================================================== WINDOWS */

#include <windows.h>

static HANDLE g_ssh_proc = NULL;
static HANDLE g_job = NULL;

typedef struct { volatile sig_atomic_t *stop; volatile int port; int verbose; } relay_ctx;

static DWORD WINAPI
relay_thread_live(LPVOID arg)
{
	relay_ctx *rc = arg;
	wld_relay_serve("127.0.0.1", "0", rc->verbose, 0, rc->stop, (int *)&rc->port);
	return 0;
}

typedef struct { HANDLE pipe; volatile int found; char host[256]; volatile int port; } reader_ctx;

static DWORD WINAPI
reader_thread(LPVOID arg)
{
	reader_ctx *rc = arg;
	char acc[16384]; size_t alen = 0;
	char buf[1024]; DWORD n;
	for (;;) {
		if (!ReadFile(rc->pipe, buf, sizeof buf, &n, NULL) || n == 0) break;
		if (!rc->found) {
			size_t room = sizeof acc - 1 - alen;
			if (room == 0) { alen = 0; room = sizeof acc - 1; }
			size_t cp = ((size_t)n < room) ? (size_t)n : room;
			memcpy(acc + alen, buf, cp);
			alen += cp; acc[alen] = '\0';
			char h[256]; int pt;
			if (parse_tcp_url(acc, h, sizeof h, &pt) == 0) {
				snprintf(rc->host, sizeof rc->host, "%s", h);
				rc->port = pt; rc->found = 1;
			}
		}
		/* keep draining after found so ssh never blocks on a full pipe */
	}
	CloseHandle(rc->pipe);
	return 0;
}

int
wld_pinggy_autotunnel(int verbose, char *local_port_out, size_t lpcap,
                      char *pub_host_out, size_t phcap, int *pub_port_out)
{
	g_verbose = verbose;

	/* 1) embedded relay on a background thread */
	static volatile sig_atomic_t stop;
	relay_ctx *rctx = calloc(1, sizeof *rctx);
	if (rctx == NULL) return -1;
	rctx->stop = &stop; rctx->verbose = verbose;
	HANDLE rt = CreateThread(NULL, 0, relay_thread_live, rctx, 0, NULL);
	if (rt == NULL) { plog("relay thread failed"); return -1; }
	CloseHandle(rt); /* detach */

	int relay_port = 0;
	for (int i = 0; i < 200; i++) {
		relay_port = rctx->port;
		if (relay_port > 0) break;
		Sleep(10);
	}
	if (relay_port <= 0) { plog("embedded relay did not start"); return -1; }
	plog("embedded relay on 127.0.0.1:%d", relay_port);
	if (local_port_out) snprintf(local_port_out, lpcap, "%d", relay_port);

	/* 2) spawn ssh -> pinggy, stdout+stderr captured through a pipe */
	SECURITY_ATTRIBUTES sa; ZeroMemory(&sa, sizeof sa);
	sa.nLength = sizeof sa; sa.bInheritHandle = TRUE;
	HANDLE rdPipe = NULL, wrPipe = NULL;
	if (!CreatePipe(&rdPipe, &wrPipe, &sa, 0)) { plog("pipe failed"); return -1; }
	SetHandleInformation(rdPipe, HANDLE_FLAG_INHERIT, 0); /* read end not inherited */
	HANDLE nul = CreateFileA("NUL", GENERIC_READ,
	    FILE_SHARE_READ | FILE_SHARE_WRITE, &sa, OPEN_EXISTING, 0, NULL);

	char cmd[256];
	snprintf(cmd, sizeof cmd,
	    "ssh -p 443 -o StrictHostKeyChecking=accept-new -o ServerAliveInterval=30 "
	    "-o ServerAliveCountMax=3 -o ExitOnForwardFailure=yes -T -R 0:localhost:%d tcp@%s",
	    relay_port, PINGGY_HOST);

	STARTUPINFOA si; ZeroMemory(&si, sizeof si); si.cb = sizeof si;
	si.dwFlags = STARTF_USESTDHANDLES;
	si.hStdOutput = wrPipe; si.hStdError = wrPipe;
	si.hStdInput = (nul != INVALID_HANDLE_VALUE) ? nul : NULL;
	PROCESS_INFORMATION pi; ZeroMemory(&pi, sizeof pi);

	plog("opening pinggy tunnel via ssh (%s)...", PINGGY_HOST);
	BOOL ok = CreateProcessA(NULL, cmd, NULL, NULL, TRUE, CREATE_NO_WINDOW,
	    NULL, NULL, &si, &pi);
	CloseHandle(wrPipe);
	if (nul != INVALID_HANDLE_VALUE) CloseHandle(nul);
	if (!ok) {
		plog("cannot start ssh (install OpenSSH Client: Settings > System > "
		     "Optional features)");
		CloseHandle(rdPipe);
		return -1;
	}
	CloseHandle(pi.hThread);
	g_ssh_proc = pi.hProcess;

	/* Job Object: if THIS process dies, ssh is killed with it. */
	g_job = CreateJobObjectA(NULL, NULL);
	if (g_job) {
		JOBOBJECT_EXTENDED_LIMIT_INFORMATION jeli; ZeroMemory(&jeli, sizeof jeli);
		jeli.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
		SetInformationJobObject(g_job, JobObjectExtendedLimitInformation, &jeli, sizeof jeli);
		AssignProcessToJobObject(g_job, pi.hProcess);
	}

	reader_ctx *rd = calloc(1, sizeof *rd);
	if (rd == NULL) { CloseHandle(rdPipe); return -1; }
	rd->pipe = rdPipe;
	HANDLE rdt = CreateThread(NULL, 0, reader_thread, rd, 0, NULL);
	if (rdt == NULL) { plog("reader thread failed"); CloseHandle(rdPipe); return -1; }
	CloseHandle(rdt);

	/* 3) wait up to ~25s for pinggy to assign the public address */
	for (int i = 0; i < 2500; i++) {
		if (rd->found) break;
		if (WaitForSingleObject(pi.hProcess, 0) == WAIT_OBJECT_0) {
			DWORD ec = 0; GetExitCodeProcess(pi.hProcess, &ec);
			plog("ssh exited before a tunnel was assigned (rc=%lu)", ec);
			return -1;
		}
		Sleep(10);
	}
	if (!rd->found) { plog("no tunnel address from pinggy (timeout)"); return -1; }

	if (pub_host_out) snprintf(pub_host_out, phcap, "%s", rd->host);
	if (pub_port_out) *pub_port_out = rd->port;
	plog("tunnel up: public %s:%d", rd->host, rd->port);
	return 0;
}

void
wld_pinggy_drain(int max_ms)
{
	if (g_ssh_proc == NULL) return;
	/* Wait for the embedded relay's live connections to drain, a short grace
	 * for ssh to push the last bytes, then tear the tunnel down. */
	int waited = 0; const int step = 20;
	while (waited < max_ms) {
		if (wld_relay_live_conns() == 0 && waited >= 300) break;
		Sleep(step); waited += step;
	}
	Sleep(1000);
	TerminateProcess(g_ssh_proc, 0);
	CloseHandle(g_ssh_proc); g_ssh_proc = NULL;
	if (g_job) { CloseHandle(g_job); g_job = NULL; }
}

#else /* ============================================================== POSIX */

#include <pthread.h>
#include <time.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/wait.h>
#ifdef __linux__
#  include <sys/prctl.h>
#endif

static pid_t g_ssh_pid = -1;

/* ---- embedded relay thread ---------------------------------------------- */

typedef struct { volatile sig_atomic_t *stop; volatile int port; int verbose; } relay_ctx;

static void *
relay_thread_live(void *arg)
{
	relay_ctx *rc = arg;
	wld_relay_serve("127.0.0.1", "0", rc->verbose, 0, rc->stop, (int *)&rc->port);
	return NULL;
}

/* ---- ssh child output reader -------------------------------------------- */

typedef struct {
	int fd;
	volatile int found;
	char host[256];
	volatile int port;
} reader_ctx;

static void *
reader_thread(void *arg)
{
	reader_ctx *rc = arg;
	char acc[16384];
	size_t alen = 0;
	char buf[1024];
	for (;;) {
		ssize_t n = read(rc->fd, buf, sizeof buf);
		if (n <= 0) break;
		if (!rc->found) {
			size_t room = sizeof acc - 1 - alen;
			if (room == 0) { alen = 0; room = sizeof acc - 1; } /* reset on overflow */
			size_t cp = ((size_t)n < room) ? (size_t)n : room;
			memcpy(acc + alen, buf, cp);
			alen += cp; acc[alen] = '\0';
			char h[256]; int pt;
			if (parse_tcp_url(acc, h, sizeof h, &pt) == 0) {
				snprintf(rc->host, sizeof rc->host, "%s", h);
				rc->port = pt;
				rc->found = 1;
			}
		}
		/* keep draining after found so ssh never blocks on a full pipe */
	}
	close(rc->fd);
	return NULL;
}

/* ---- orchestrator ------------------------------------------------------- */

int
wld_pinggy_autotunnel(int verbose, char *local_port_out, size_t lpcap,
                      char *pub_host_out, size_t phcap, int *pub_port_out)
{
	g_verbose = verbose;

	/* 1) embedded relay */
	static volatile sig_atomic_t stop;
	relay_ctx *rctx = calloc(1, sizeof *rctx);
	if (rctx == NULL) return -1;
	rctx->stop = &stop; rctx->verbose = verbose;
	pthread_t rt;
	if (pthread_create(&rt, NULL, relay_thread_live, rctx) != 0) { plog("relay thread failed"); return -1; }
	pthread_detach(rt);

	int relay_port = 0;
	for (int i = 0; i < 200; i++) {
		relay_port = rctx->port;
		if (relay_port > 0) break;
		struct timespec ts = { 0, 10 * 1000 * 1000 };
		nanosleep(&ts, NULL);
	}
	if (relay_port <= 0) { plog("embedded relay did not start"); return -1; }
	plog("embedded relay on 127.0.0.1:%d", relay_port);
	if (local_port_out) snprintf(local_port_out, lpcap, "%d", relay_port);

	/* 2) spawn ssh -> pinggy, capturing its output */
	int pipefd[2];
	if (pipe(pipefd) != 0) { plog("pipe failed"); return -1; }

	char fwd[64];
	snprintf(fwd, sizeof fwd, "0:localhost:%d", relay_port);

	plog("opening pinggy tunnel via ssh (%s)...", PINGGY_HOST);
	pid_t pid = fork();
	if (pid < 0) { plog("fork failed"); close(pipefd[0]); close(pipefd[1]); return -1; }
	if (pid == 0) {
		/* child: ssh stdout+stderr -> pipe; die if parent dies */
		dup2(pipefd[1], STDOUT_FILENO);
		dup2(pipefd[1], STDERR_FILENO);
		close(pipefd[0]); close(pipefd[1]);
		int nul = open("/dev/null", O_RDONLY);
		if (nul >= 0) { dup2(nul, STDIN_FILENO); close(nul); }
#ifdef __linux__
		prctl(PR_SET_PDEATHSIG, SIGTERM);
#endif
		execlp("ssh", "ssh", "-p", "443",
		    "-o", "StrictHostKeyChecking=accept-new",
		    "-o", "ServerAliveInterval=30",
		    "-o", "ServerAliveCountMax=3",
		    "-o", "ExitOnForwardFailure=yes",
		    "-T", "-R", fwd, "tcp@" PINGGY_HOST, (char *)NULL);
		/* exec failed */
		dprintf(STDERR_FILENO, "wld-pinggy: cannot exec ssh (is it installed?)\n");
		_exit(127);
	}

	close(pipefd[1]);
	g_ssh_pid = pid;

	reader_ctx *rd = calloc(1, sizeof *rd);
	if (rd == NULL) { close(pipefd[0]); return -1; }
	rd->fd = pipefd[0];
	pthread_t rdt;
	if (pthread_create(&rdt, NULL, reader_thread, rd) != 0) { plog("reader thread failed"); close(pipefd[0]); return -1; }
	pthread_detach(rdt);

	/* 3) wait up to ~25s for pinggy to assign the public address */
	for (int i = 0; i < 2500; i++) {
		if (rd->found) break;
		/* detect early ssh death */
		int st;
		if (waitpid(pid, &st, WNOHANG) == pid) {
			plog("ssh exited before a tunnel was assigned (rc=%d)",
			    WIFEXITED(st) ? WEXITSTATUS(st) : -1);
			g_ssh_pid = -1;
			return -1;
		}
		struct timespec ts = { 0, 10 * 1000 * 1000 };
		nanosleep(&ts, NULL);
	}
	if (!rd->found) { plog("no tunnel address from pinggy (timeout)"); return -1; }

	if (pub_host_out) snprintf(pub_host_out, phcap, "%s", rd->host);
	if (pub_port_out) *pub_port_out = rd->port;
	plog("tunnel up: public %s:%d", rd->host, rd->port);
	return 0;
}

void
wld_pinggy_drain(int max_ms)
{
	if (g_ssh_pid <= 0) return;
	/*
	 * The embedded relay runs in a thread of THIS process and ssh forwards
	 * from it. On exit, wait for the relay to flush and close its connections
	 * (live conns -> 0), then a short grace for ssh to push the last bytes to
	 * the peer, before tearing the tunnel down — so a one-shot transfer is not
	 * truncated.
	 */
	int waited = 0;
	const int step = 20;
	while (waited < max_ms) {
		if (wld_relay_live_conns() == 0 && waited >= 300) break;
		struct timespec ts = { 0, step * 1000 * 1000 };
		nanosleep(&ts, NULL);
		waited += step;
	}
	struct timespec grace = { 1, 0 }; /* let ssh forward the last buffer */
	nanosleep(&grace, NULL);
	kill(g_ssh_pid, SIGTERM);
	g_ssh_pid = -1;
}

#endif /* POSIX */
