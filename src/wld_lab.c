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

#else /* ---------------------------------------------------------------- POSIX */

#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/types.h>
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

/* Absolute path to this executable (Linux). Caller frees, or NULL. */
static char *
self_path(const char *argv0)
{
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
"           but has a real executable at /proc/<pid>/exe and a heap/\n"
"           stack+mapped libs (genuine kthreads have none).\n"
"  Hunt   : for p in /proc/[0-9]*; do n=$(tr -d '\\0' <$p/comm);\n"
"           case $n in \\[*\\]) readlink $p/exe 2>/dev/null && \\\n"
"             echo \"FAKE KTHREAD: $p ($n)\";; esac; done\n"
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
"           stat -c '%n mtime=%Y ctime=%Z' ~/.wetland-lab   # ctime>>mtime\n"
"  ─────────────────────────────────────────────────────────────\n", stderr);
}

static void
hint_beacon(void)
{
	fputs(
"\n  ── detection hint ───────────────────────────────────────────\n"
"  ATT&CK : T1071.001 (Web C2) / T1573 (Encrypted Channel) / T1008\n"
"  IOCs   : regular outbound connections to :443 at a fixed cadence\n"
"           (+/- jitter), tiny request, little/no response. NOT real\n"
"           TLS, so a TLS parser / JA3 pipeline sees a malformed or\n"
"           unknown fingerprint on 443 -> itself a signal.\n"
"  Hunt   : NetFlow/Zeek: beaconing by connection-interval regularity;\n"
"           443 traffic with no TLS ClientHello; low bytes-up/down ratio.\n"
"  ─────────────────────────────────────────────────────────────\n", stderr);
}

/* ---- technique: masquerade ---------------------------------------------- */

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

	/* Copy the name out first: argv[] memory is about to be wiped and `name`
	 * may point into it (it came from argv). */
	char fake[256];
	snprintf(fake, sizeof fake, "%s", name);

	char orig[64] = "?";
#ifdef __linux__
	prctl(PR_GET_NAME, orig, 0, 0, 0);
#endif
	labf("masquerade: pid=%ld original comm='%s' argv0='%s'",
	    (long)getpid(), orig, origv[0]);

	/* 1) kernel-visible comm (truncated to 15 chars by the kernel) */
#ifdef __linux__
	prctl(PR_SET_NAME, fake, 0, 0, 0);
#endif
	/* 2) rewrite the contiguous argv region so ps / /proc/pid/cmdline lie */
	char *start = origv[0];
	char *end   = origv[origc - 1] + strlen(origv[origc - 1]) + 1;
	size_t span = (size_t)(end - start);
	if (span > 1) {
		memset(start, 0, span);
		strncpy(start, fake, span - 1);
	}

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
		struct timespec times[2];
		times[0] = st.st_atim;
		times[1] = st.st_mtim;
		if (utimensat(AT_FDCWD, dest, times, 0) == 0)
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

static int
do_beacon(int argc, char **argv)
{
	const char *host = NULL, *port = "443";
	long interval = 30, jitter = 20, count = 0, size = 64;
	for (int i = 0; i < argc; i++) {
		if (is_opt(argv[i], "--to") && i + 1 < argc) {
			char *s = argv[++i];
			char *c = strrchr(s, ':');
			if (c) { *c = '\0'; host = s; port = c + 1; }
			else host = s;
		}
		else if (is_opt(argv[i], "--interval") && i + 1 < argc) interval = atol(argv[++i]);
		else if (is_opt(argv[i], "--jitter") && i + 1 < argc) jitter = atol(argv[++i]);
		else if (is_opt(argv[i], "--count") && i + 1 < argc) count = atol(argv[++i]);
		else if (is_opt(argv[i], "--size") && i + 1 < argc) size = atol(argv[++i]);
		else { labf("beacon: unknown arg '%s'", argv[i]); return 2; }
	}
	if (host == NULL) { labf("beacon: need --to HOST[:PORT]"); return 2; }
	if (size < 1) size = 1;
	if (size > 4096) size = 4096;
	if (interval < 1) interval = 1;
	if (jitter < 0) jitter = 0;
	if (jitter > 90) jitter = 90;

	if (wld_net_startup() != 0) { labf("beacon: net init failed"); return 1; }
	signal(SIGINT, on_sigint);
	srand((unsigned)(time(NULL) ^ getpid()));

	labf("beacon: -> %s:%s every %lds +/-%ld%% size=%ldB count=%s",
	    host, port, interval, jitter, size,
	    count ? "(fixed)" : "inf (Ctrl-C to stop)");
	hint_beacon();

	unsigned char *buf = malloc((size_t)size);
	if (buf == NULL) return 1;

	long sent = 0;
	while (!g_stop && (count == 0 || sent < count)) {
		int fd = wld_tcp_connect(host, port);
		char ts[32]; time_t now = time(NULL);
		strftime(ts, sizeof ts, "%H:%M:%S", localtime(&now));
		if (fd >= 0) {
			for (long i = 0; i < size; i++) buf[i] = (unsigned char)rand();
			wld_write_all(fd, buf, (size_t)size);
			char rb[64];
			(void)wld_sock_read(fd, rb, sizeof rb); /* best-effort */
			wld_closesocket(fd);
			labf("beacon #%ld @%s: sent %ldB to %s:%s", sent + 1, ts, size, host, port);
		} else {
			labf("beacon #%ld @%s: connect to %s:%s failed", sent + 1, ts, host, port);
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
	labf("beacon: stopped after %ld beacon(s).", sent);
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
"  beacon --to HOST[:PORT] [--interval S] [--jitter PCT] [--count N] [--size B]\n"
"      T1071/T1573: periodic jittered outbound beacons (default :443, 30s,\n"
"      20%, infinite). NOT real TLS.\n"
"\n"
"  uninstall        remove every " LAB_MARKER " artifact this tool creates.\n"
"  detections       print the ATT&CK -> detection mapping for all techniques.\n",
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
	int sub_argc = argc - (ti + 1);
	char **sub_argv = argv + (ti + 1);

	if (strcmp(tech, "masquerade") == 0)
		return do_masquerade(sub_argc, sub_argv, argv, argc);
	if (strcmp(tech, "persist") == 0)
		return do_persist(sub_argc, sub_argv);
	if (strcmp(tech, "hide") == 0)
		return do_hide(sub_argc, sub_argv, argv[0]);
	if (strcmp(tech, "beacon") == 0)
		return do_beacon(sub_argc, sub_argv);
	if (strcmp(tech, "uninstall") == 0)
		return do_uninstall();
	if (strcmp(tech, "detections") == 0) {
		fprintf(stderr, "wld lab — ATT&CK detection mapping\n");
		hint_masquerade(); hint_persist(); hint_hide(); hint_beacon();
		return 0;
	}
	if (strcmp(tech, "help") == 0 || strcmp(tech, "-h") == 0)
		return lab_usage();

	labf("unknown technique '%s'", tech);
	return lab_usage();
}

#endif /* POSIX */
