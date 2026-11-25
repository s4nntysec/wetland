/*
 * wetland - zero-config tunnel selector (see wld_autotunnel.h).
 */
#include "wld_autotunnel.h"
#include "wld_bore.h"
#include "wld_frp.h"
#include "wld_pinggy.h"
#include "wld_natmap.h"
#include "wld_crypto.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Deterministic public-port request derived from the secret (for frp/bore on a
 * server you control; public servers are asked to choose instead). */
static int
derived_port(const char *secret)
{
	uint8_t sel[WLD_ADDR_LEN];
	if (wld_derive(secret, 0, sel, NULL, NULL) != 0) return 0;
	uint64_t v = 0;
	for (int i = 0; i < 8; i++) v = (v << 8) | sel[i];
	return 1024 + (int)(v % 64000);
}

int
wld_open_tunnel(const char *secret, int verbose,
                char *lp, size_t lpc, char *ph, size_t phc, int *pp,
                long *expiry_secs)
{
	if (expiry_secs) *expiry_secs = 0;

	const char *frp_server = getenv("WLD_FRP_SERVER");
	const char *bore_host  = getenv("WLD_BORE_HOST");

	if (frp_server != NULL && frp_server[0] != '\0') {
		const char *frp_port  = getenv("WLD_FRP_PORT");  /* default 7000 */
		const char *frp_token = getenv("WLD_FRP_TOKEN");
		const char *frp_rport = getenv("WLD_FRP_REMOTE_PORT");
		int req = (frp_rport && frp_rport[0]) ? atoi(frp_rport) : derived_port(secret);
		fprintf(stderr, "wld: no relay configured - embedded relay + frp tunnel "
		    "via %s...\n", frp_server);
		return wld_frp_autotunnel(frp_server, frp_port, frp_token, req, verbose,
		    lp, lpc, ph, phc, pp);
	}
	if (bore_host != NULL && bore_host[0] != '\0') {
		const char *bore_rport = getenv("WLD_BORE_REMOTE_PORT");
		int req = (bore_rport && bore_rport[0]) ? atoi(bore_rport) : 0;
		fprintf(stderr, "wld: no relay configured - embedded relay + %s "
		    "tunnel...\n", bore_host);
		return wld_bore_autotunnel(bore_host, req, verbose, lp, lpc, ph, phc, pp);
	}
#ifdef _WIN32
	/* Windows default: open a port on the local router directly - no relay, no
	 * separate server, no third-party service (NAT-PMP, then UPnP-IGD). Falls
	 * through to the pinggy tunnel if the router won't map (CGNAT/disabled). */
	{
		int rm = wld_natmap_open(verbose, lp, lpc, ph, phc, pp);
		if (rm == 0) {
			fprintf(stderr, "wld: no relay configured - opened a port on the "
			    "router (NAT-PMP/UPnP); no tunnel needed\n");
			return 0;
		}
		fprintf(stderr, "wld: router port-mapping unavailable - trying a public "
		    "tunnel instead...\n");
	}
	/* Native bore (no ssh dependency) to bore.pub by default — reliable on
	 * Windows where the ssh-based pinggy path is finicky. Explicit
	 * WLD_BORE_HOST was already handled above. */
	{
		fprintf(stderr, "wld: no relay configured - embedded relay + bore tunnel "
		    "(bore.pub)...\n");
		int rb = wld_bore_autotunnel("bore.pub", 0, verbose, lp, lpc, ph, phc, pp);
		if (rb == 0) return 0;
		fprintf(stderr, "wld: bore tunnel failed - trying pinggy (ssh)...\n");
	}
#endif
	fprintf(stderr, "wld: no relay configured - embedded relay + pinggy tunnel...\n");
	int r = wld_pinggy_autotunnel(verbose, lp, lpc, ph, phc, pp);
	if (r == 0 && expiry_secs) *expiry_secs = 55 * 60; /* pinggy free ~60 min */
	return r;
}

void
wld_tunnel_drain_all(int max_ms)
{
	wld_natmap_drain(max_ms);
	wld_bore_drain(max_ms);
	wld_frp_drain(max_ms);
	wld_pinggy_drain(max_ms);
}
