/*
 * wetland — Windows NAT port-mapping backend (see wld_natmap.h).
 */
#ifdef _WIN32
#  ifndef _WIN32_WINNT
#    define _WIN32_WINNT 0x0601   /* Windows 7+: inet_ntop, FirstGatewayAddress */
#  endif
#endif

#include "wld_natmap.h"
#include "wld_relay.h"
#include "wld_compat.h"
#include "wld_net.h"

#include <signal.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef _WIN32  /* ===================================================== POSIX stub */

int
wld_natmap_open(int verbose, char *lp, size_t lpc, char *ph, size_t phc, int *pp)
{
	(void)verbose; (void)lp; (void)lpc; (void)ph; (void)phc; (void)pp;
	return -1; /* Windows only */
}
void wld_natmap_drain(int max_ms) { (void)max_ms; }

#else /* ============================================================== WINDOWS */

#include <windows.h>
#include <iphlpapi.h>

static int g_verbose;

static void
plog(const char *fmt, ...)
{
	if (!g_verbose) return;
	va_list ap;
	fputs("[wld-natmap] ", stderr);
	va_start(ap, fmt); vfprintf(stderr, fmt, ap); va_end(ap);
	fputc('\n', stderr);
}

/* ---- embedded relay on a background thread (bound on all interfaces) ----- */

static volatile sig_atomic_t g_stop;
static HANDLE g_relay_thread = NULL;
static volatile int g_relay_port;

static DWORD WINAPI
relay_thread(LPVOID a)
{
	(void)a;
	wld_relay_serve("0.0.0.0", "0", g_verbose, 0, &g_stop, (int *)&g_relay_port);
	return 0;
}

static int
start_relay(void)
{
	g_stop = 0; g_relay_port = 0;
	g_relay_thread = CreateThread(NULL, 0, relay_thread, NULL, 0, NULL);
	if (g_relay_thread == NULL) return -1;
	for (int i = 0; i < 200; i++) {
		if (g_relay_port > 0) return g_relay_port;
		Sleep(10);
	}
	return (g_relay_port > 0) ? g_relay_port : -1;
}

static void
stop_relay(void)
{
	if (g_relay_thread == NULL) return;
	g_stop = 1;
	WaitForSingleObject(g_relay_thread, 1500); /* poll timeout is 1000ms */
	CloseHandle(g_relay_thread);
	g_relay_thread = NULL;
}

/* ---- teardown state ----------------------------------------------------- */

static int  g_method;            /* 0 none, 1 NAT-PMP, 2 UPnP */
static char g_gw[46];
static char g_lan[46];
static int  g_internal_port;
static int  g_external_port;
/* UPnP control endpoint for DeletePortMapping */
static char g_up_host[256];
static char g_up_port[8];
static char g_up_path[1024];
static char g_up_svc[128];

/* ---- small string / net helpers ----------------------------------------- */

static int
ci_eq(const char *a, const char *b, size_t n)
{
	for (size_t i = 0; i < n; i++) {
		char ca = a[i], cb = b[i];
		if (ca >= 'A' && ca <= 'Z') ca += 32;
		if (cb >= 'A' && cb <= 'Z') cb += 32;
		if (ca != cb) return 0;
		if (ca == 0) return 1;
	}
	return 1;
}

/* case-insensitive strstr */
static const char *
ci_strstr(const char *hay, const char *needle)
{
	size_t nl = strlen(needle);
	if (nl == 0) return hay;
	for (const char *p = hay; *p; p++)
		if (ci_eq(p, needle, nl)) return p;
	return NULL;
}

static int
is_private_v4(const char *ip)
{
	unsigned a, b, c, d;
	if (sscanf(ip, "%u.%u.%u.%u", &a, &b, &c, &d) != 4) return 1;
	if (a == 10) return 1;
	if (a == 172 && b >= 16 && b <= 31) return 1;
	if (a == 192 && b == 168) return 1;
	if (a == 100 && b >= 64 && b <= 127) return 1; /* 100.64/10 CGNAT */
	if (a == 127 || a == 0 || a >= 224) return 1;
	if (a == 169 && b == 254) return 1;            /* link-local */
	return 0;
}

/* Default IPv4 gateway + our LAN IP via GetAdaptersAddresses. */
static int
find_gateway(char *gw, size_t gwc, char *lan, size_t lanc)
{
	ULONG sz = 16384;
	IP_ADAPTER_ADDRESSES *aa = malloc(sz);
	if (aa == NULL) return -1;
	ULONG flags = GAA_FLAG_INCLUDE_GATEWAYS | GAA_FLAG_SKIP_DNS_SERVER |
	    GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_ANYCAST;
	ULONG r = GetAdaptersAddresses(AF_INET, flags, NULL, aa, &sz);
	if (r == ERROR_BUFFER_OVERFLOW) {
		free(aa); aa = malloc(sz);
		if (aa == NULL) return -1;
		r = GetAdaptersAddresses(AF_INET, flags, NULL, aa, &sz);
	}
	if (r != NO_ERROR) { free(aa); return -1; }

	int found = -1;
	for (IP_ADAPTER_ADDRESSES *p = aa; p && found != 0; p = p->Next) {
		if (p->OperStatus != IfOperStatusUp) continue;
		if (p->IfType == IF_TYPE_SOFTWARE_LOOPBACK) continue;
		if (p->FirstGatewayAddress == NULL) continue;
		struct sockaddr *gs = p->FirstGatewayAddress->Address.lpSockaddr;
		if (gs == NULL || gs->sa_family != AF_INET) continue;
		struct sockaddr_in *gin = (struct sockaddr_in *)gs;

		struct sockaddr_in *lin = NULL;
		for (IP_ADAPTER_UNICAST_ADDRESS *u = p->FirstUnicastAddress; u; u = u->Next) {
			if (u->Address.lpSockaddr->sa_family == AF_INET) {
				lin = (struct sockaddr_in *)u->Address.lpSockaddr; break;
			}
		}
		if (lin == NULL) continue;
		if (inet_ntop(AF_INET, &gin->sin_addr, gw, gwc) == NULL) continue;
		if (inet_ntop(AF_INET, &lin->sin_addr, lan, lanc) == NULL) continue;
		found = 0;
	}
	free(aa);
	return found;
}

/* One send/recv TCP transaction; returns bytes read (resp NUL-terminated), or -1. */
static int
tcp_txn(const char *host, const char *port, const char *req, int reqlen,
        char *resp, int rcap)
{
	int fd = wld_tcp_connect(host, port);
	if (fd < 0) return -1;
	int off = 0;
	while (off < reqlen) {
		int w = send((SOCKET)fd, req + off, reqlen - off, 0);
		if (w <= 0) { wld_closesocket(fd); return -1; }
		off += w;
	}
	int total = 0;
	for (;;) {
		int n = recv((SOCKET)fd, resp + total, rcap - 1 - total, 0);
		if (n <= 0) break;
		total += n;
		if (total >= rcap - 1) break;
	}
	resp[total] = '\0';
	wld_closesocket(fd);
	return total;
}

/* Extract the text of the first <tag>...</tag> (namespace-prefix tolerant). */
static int
xml_val(const char *xml, const char *tag, char *out, size_t cap)
{
	char open[64];
	snprintf(open, sizeof open, "<%s", tag);
	const char *p = ci_strstr(xml, open);
	if (p == NULL) return -1;
	p = strchr(p, '>');
	if (p == NULL) return -1;
	p++;
	size_t i = 0;
	while (*p && *p != '<' && i < cap - 1) out[i++] = *p++;
	out[i] = '\0';
	return 0;
}

/* ---- NAT-PMP (RFC 6886) ------------------------------------------------- */

static void be16(unsigned char *b, unsigned v) { b[0] = (v >> 8) & 0xff; b[1] = v & 0xff; }
static void be32(unsigned char *b, unsigned long v)
{ b[0] = (v >> 24) & 0xff; b[1] = (v >> 16) & 0xff; b[2] = (v >> 8) & 0xff; b[3] = v & 0xff; }
static unsigned rd16(const unsigned char *b) { return (b[0] << 8) | b[1]; }

static int
natpmp_udp(const char *gw, const unsigned char *req, int reqlen,
           unsigned char *resp, int rcap)
{
	SOCKET s = socket(AF_INET, SOCK_DGRAM, 0);
	if (s == INVALID_SOCKET) return -1;
	DWORD to = 600;
	setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (char *)&to, sizeof to);
	struct sockaddr_in a; memset(&a, 0, sizeof a);
	a.sin_family = AF_INET; a.sin_port = htons(5351);
	inet_pton(AF_INET, gw, &a.sin_addr);
	int got = -1;
	for (int t = 0; t < 3 && got < 0; t++) {
		sendto(s, (const char *)req, reqlen, 0, (struct sockaddr *)&a, sizeof a);
		int n = recvfrom(s, (char *)resp, rcap, 0, NULL, NULL);
		if (n > 0) got = n;
	}
	closesocket(s);
	return got;
}

/* External address + TCP map. Returns 0 on success. */
static int
natpmp_map(const char *gw, int internal_port, char *ext_ip, size_t extc, int *ext_port)
{
	unsigned char req[12], resp[32];

	/* external address request */
	req[0] = 0; req[1] = 0;
	int n = natpmp_udp(gw, req, 2, resp, sizeof resp);
	if (n < 12 || resp[1] != 128 || rd16(resp + 2) != 0) return -1;
	snprintf(ext_ip, extc, "%u.%u.%u.%u", resp[8], resp[9], resp[10], resp[11]);
	if (is_private_v4(ext_ip)) {
		plog("NAT-PMP: external IP %s is private (CGNAT/double-NAT) — not reachable", ext_ip);
		return -1;
	}

	/* map TCP: internal_port -> suggested same, lifetime 3600 */
	memset(req, 0, sizeof req);
	req[0] = 0; req[1] = 2;
	be16(req + 4, (unsigned)internal_port);
	be16(req + 6, (unsigned)internal_port);
	be32(req + 8, 3600);
	n = natpmp_udp(gw, req, 12, resp, sizeof resp);
	if (n < 16 || resp[1] != 130 || rd16(resp + 2) != 0) return -1;
	*ext_port = (int)rd16(resp + 10);
	return 0;
}

static void
natpmp_unmap(const char *gw, int internal_port)
{
	unsigned char req[12], resp[32];
	memset(req, 0, sizeof req);
	req[0] = 0; req[1] = 2;
	be16(req + 4, (unsigned)internal_port);
	be16(req + 6, 0);
	be32(req + 8, 0); /* lifetime 0 = delete */
	(void)natpmp_udp(gw, req, 12, resp, sizeof resp);
}

/* ---- UPnP-IGD ----------------------------------------------------------- */

/* SSDP discover -> LOCATION url of an IGD. */
static int
ssdp_discover(char *loc, size_t loccap)
{
	SOCKET s = socket(AF_INET, SOCK_DGRAM, 0);
	if (s == INVALID_SOCKET) return -1;
	DWORD to = 1500;
	setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (char *)&to, sizeof to);
	struct sockaddr_in dst; memset(&dst, 0, sizeof dst);
	dst.sin_family = AF_INET; dst.sin_port = htons(1900);
	inet_pton(AF_INET, "239.255.255.250", &dst.sin_addr);

	const char *sts[] = {
		"urn:schemas-upnp-org:device:InternetGatewayDevice:1",
		"urn:schemas-upnp-org:service:WANIPConnection:1",
		"urn:schemas-upnp-org:service:WANPPPConnection:1", NULL
	};
	for (int k = 0; sts[k]; k++) {
		char m[400];
		int ml = snprintf(m, sizeof m,
		    "M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\n"
		    "MAN: \"ssdp:discover\"\r\nMX: 2\r\nST: %s\r\n\r\n", sts[k]);
		sendto(s, m, ml, 0, (struct sockaddr *)&dst, sizeof dst);
	}
	int rc = -1;
	for (int i = 0; i < 24 && rc < 0; i++) {
		char buf[2048];
		int n = recvfrom(s, buf, sizeof buf - 1, 0, NULL, NULL);
		if (n <= 0) break;
		buf[n] = '\0';
		const char *L = ci_strstr(buf, "\nLOCATION:");
		if (L == NULL) L = ci_strstr(buf, "\nlocation:");
		if (L) {
			L += 10;
			while (*L == ' ' || *L == '\t') L++;
			size_t j = 0;
			while (*L && *L != '\r' && *L != '\n' && j < loccap - 1) loc[j++] = *L++;
			loc[j] = '\0';
			rc = 0;
		}
	}
	closesocket(s);
	return rc;
}

/* Split "http://host[:port]/path" */
static int
url_split(const char *url, char *host, size_t hc, char *port, size_t pc,
          char *path, size_t pathc)
{
	const char *p = ci_strstr(url, "http://");
	if (p == NULL) return -1;
	p += 7;
	size_t i = 0;
	while (*p && *p != ':' && *p != '/' && i < hc - 1) host[i++] = *p++;
	host[i] = '\0';
	snprintf(port, pc, "%s", "80");
	if (*p == ':') {
		p++; i = 0;
		while (*p && *p != '/' && i < pc - 1) port[i++] = *p++;
		port[i] = '\0';
	}
	if (*p == '/') snprintf(path, pathc, "%s", p);
	else snprintf(path, pathc, "/");
	return 0;
}

/* From the device description, find the WAN connection service + its controlURL. */
static int
find_wan_service(const char *desc, char *svc, size_t svcc, char *ctrl, size_t ctrlc)
{
	const char *types[] = {
		"urn:schemas-upnp-org:service:WANIPConnection:1",
		"urn:schemas-upnp-org:service:WANPPPConnection:1",
		"urn:schemas-upnp-org:service:WANIPConnection:2", NULL
	};
	for (int k = 0; types[k]; k++) {
		const char *st = ci_strstr(desc, types[k]);
		if (st == NULL) continue;
		const char *cu = ci_strstr(st, "<controlURL>");
		if (cu == NULL) continue;
		cu += 12;
		size_t i = 0;
		while (*cu && *cu != '<' && i < ctrlc - 1) ctrl[i++] = *cu++;
		ctrl[i] = '\0';
		snprintf(svc, svcc, "%s", types[k]);
		return 0;
	}
	return -1;
}

/* SOAP call to the control endpoint; response (NUL-terminated) in resp. */
static int
soap_call(const char *host, const char *port, const char *path, const char *svc,
          const char *action, const char *args, char *resp, int rcap)
{
	char body[1024];
	int bl = snprintf(body, sizeof body,
	    "<?xml version=\"1.0\"?>\r\n"
	    "<s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" "
	    "s:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\">"
	    "<s:Body><u:%s xmlns:u=\"%s\">%s</u:%s></s:Body></s:Envelope>",
	    action, svc, args ? args : "", action);

	char req[2048];
	int rl = snprintf(req, sizeof req,
	    "POST %s HTTP/1.1\r\nHost: %s:%s\r\n"
	    "SOAPAction: \"%s#%s\"\r\n"
	    "Content-Type: text/xml; charset=\"utf-8\"\r\n"
	    "Content-Length: %d\r\nConnection: close\r\n\r\n%s",
	    path, host, port, svc, action, bl, body);

	return tcp_txn(host, port, req, rl, resp, rcap);
}

static int
http_ok(const char *resp)
{
	/* status line "HTTP/1.x 200 ..." */
	const char *sp = strchr(resp, ' ');
	return sp && sp[1] == '2' && sp[2] == '0' && sp[3] == '0';
}

static int
upnp_map(int internal_port, const char *lan, char *ext_ip, size_t extc, int *ext_port)
{
	char loc[1024];
	if (ssdp_discover(loc, sizeof loc) != 0) { plog("UPnP: no IGD responded to SSDP"); return -1; }
	plog("UPnP: IGD description at %s", loc);

	char host[256], port[8], path[1024];
	if (url_split(loc, host, sizeof host, port, sizeof port, path, sizeof path) != 0) return -1;

	char getreq[1024], desc[16384];
	int gl = snprintf(getreq, sizeof getreq,
	    "GET %s HTTP/1.1\r\nHost: %s:%s\r\nConnection: close\r\n\r\n", path, host, port);
	if (tcp_txn(host, port, getreq, gl, desc, sizeof desc) <= 0) return -1;

	char svc[128], ctrl[1024];
	if (find_wan_service(desc, svc, sizeof svc, ctrl, sizeof ctrl) != 0) {
		plog("UPnP: no WAN connection service in description");
		return -1;
	}
	/* controlURL may be absolute or relative */
	char cpath[1024];
	if (ci_strstr(ctrl, "http://") == ctrl) {
		char ch[256], cp[8];
		if (url_split(ctrl, ch, sizeof ch, cp, sizeof cp, cpath, sizeof cpath) == 0) {
			snprintf(host, sizeof host, "%s", ch);
			snprintf(port, sizeof port, "%s", cp);
		}
	} else {
		snprintf(cpath, sizeof cpath, "%s%s", ctrl[0] == '/' ? "" : "/", ctrl);
	}

	char resp[8192];
	/* external IP */
	if (soap_call(host, port, cpath, svc, "GetExternalIPAddress", "", resp, sizeof resp) <= 0
	    || !http_ok(resp)) {
		plog("UPnP: GetExternalIPAddress failed"); return -1;
	}
	if (xml_val(resp, "NewExternalIPAddress", ext_ip, extc) != 0) return -1;
	if (is_private_v4(ext_ip)) {
		plog("UPnP: external IP %s is private (CGNAT/double-NAT) — not reachable", ext_ip);
		return -1;
	}

	/* add mapping ext==internal */
	char args[512];
	snprintf(args, sizeof args,
	    "<NewRemoteHost></NewRemoteHost><NewExternalPort>%d</NewExternalPort>"
	    "<NewProtocol>TCP</NewProtocol><NewInternalPort>%d</NewInternalPort>"
	    "<NewInternalClient>%s</NewInternalClient><NewEnabled>1</NewEnabled>"
	    "<NewPortMappingDescription>wetland</NewPortMappingDescription>"
	    "<NewLeaseDuration>0</NewLeaseDuration>",
	    internal_port, internal_port, lan);
	if (soap_call(host, port, cpath, svc, "AddPortMapping", args, resp, sizeof resp) <= 0
	    || !http_ok(resp)) {
		plog("UPnP: AddPortMapping failed"); return -1;
	}
	*ext_port = internal_port;
	/* remember for teardown */
	snprintf(g_up_host, sizeof g_up_host, "%s", host);
	snprintf(g_up_port, sizeof g_up_port, "%s", port);
	snprintf(g_up_path, sizeof g_up_path, "%s", cpath);
	snprintf(g_up_svc, sizeof g_up_svc, "%s", svc);
	return 0;
}

static void
upnp_unmap(int external_port)
{
	if (g_up_host[0] == '\0') return;
	char args[256], resp[4096];
	snprintf(args, sizeof args,
	    "<NewRemoteHost></NewRemoteHost><NewExternalPort>%d</NewExternalPort>"
	    "<NewProtocol>TCP</NewProtocol>", external_port);
	(void)soap_call(g_up_host, g_up_port, g_up_path, g_up_svc, "DeletePortMapping",
	    args, resp, sizeof resp);
}

/* ---- orchestrator ------------------------------------------------------- */

int
wld_natmap_open(int verbose, char *local_port_out, size_t lpc,
                char *pub_host_out, size_t phc, int *pub_port_out)
{
	g_verbose = verbose;
	g_method = 0;

	if (find_gateway(g_gw, sizeof g_gw, g_lan, sizeof g_lan) != 0) {
		plog("no IPv4 default gateway — cannot map a port");
		return -1;
	}
	plog("gateway %s, LAN %s", g_gw, g_lan);

	int lport = start_relay();
	if (lport <= 0) { plog("embedded relay did not start"); stop_relay(); return -1; }
	g_internal_port = lport;
	plog("embedded relay on 0.0.0.0:%d", lport);
	if (local_port_out) snprintf(local_port_out, lpc, "%d", lport);

	char ext_ip[46]; int ext_port = 0;

	if (natpmp_map(g_gw, lport, ext_ip, sizeof ext_ip, &ext_port) == 0) {
		g_method = 1; g_external_port = ext_port;
		plog("NAT-PMP mapped %s:%d -> :%d", ext_ip, ext_port, lport);
	} else if (upnp_map(lport, g_lan, ext_ip, sizeof ext_ip, &ext_port) == 0) {
		g_method = 2; g_external_port = ext_port;
		plog("UPnP mapped %s:%d -> %s:%d", ext_ip, ext_port, g_lan, lport);
	} else {
		plog("no NAT-PMP/UPnP mapping (router off/unsupported or CGNAT)");
		stop_relay();
		return -1;
	}

	if (pub_host_out) snprintf(pub_host_out, phc, "%s", ext_ip);
	if (pub_port_out) *pub_port_out = ext_port;
	return 0;
}

void
wld_natmap_drain(int max_ms)
{
	if (g_method == 0) return;
	/* let in-flight data flush, like the tunnel backends */
	int waited = 0; const int step = 20;
	while (waited < max_ms) {
		if (wld_relay_live_conns() == 0 && waited >= 300) break;
		Sleep(step); waited += step;
	}
	if (g_method == 1) natpmp_unmap(g_gw, g_internal_port);
	else if (g_method == 2) upnp_unmap(g_external_port);
	g_method = 0;
	stop_relay();
}

#endif /* WINDOWS */
