/*
 * wetland-relay — the rendezvous server (thin CLI wrapper).
 *
 * The actual serve loop lives in wld_relay.c (wld_relay_serve), so the client
 * can embed a relay in-process for the bore-style auto-tunnel.
 */
#include "wld_proto.h"
#include "wld_net.h"
#include "wld_crypto.h"
#include "wld_compat.h"
#include "wld_relay.h"

#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#ifdef _WIN32
#  include <getopt.h>
#endif

static volatile sig_atomic_t g_stop;
static void on_sig(int s) { (void)s; g_stop = 1; }

int
main(int argc, char **argv)
{
	const char *host = NULL;
	const char *port = WLD_RELAY_DEFAULT_PORT;
	int verbose = 0;
	int opt;

	while ((opt = getopt(argc, argv, "b:p:vh")) != -1) {
		switch (opt) {
		case 'b': host = optarg; break;
		case 'p': port = optarg; break;
		case 'v': verbose = 1; break;
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

	int rc = wld_relay_serve(host, port, verbose, 1, &g_stop, NULL);

	fprintf(stderr, "\nwetland-relay shutting down\n");
	wld_net_cleanup();
	return rc == 0 ? 0 : 1;
}
