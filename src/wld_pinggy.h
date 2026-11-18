/*
 * wetland — pinggy reverse-tunnel backend (zero-config, no account).
 *
 * Starts an embedded relay (127.0.0.1, ephemeral port) and exposes it on a
 * public address by spawning the system `ssh` to pinggy.io's free TCP tunnel
 * (no account). pinggy does the forwarding, so there is no proxy code here —
 * just the relay thread plus a supervised `ssh` child whose assigned public
 * `tcp://host:port` is parsed and returned.
 *
 * The only host dependency is an `ssh` client (near-ubiquitous). Free pinggy
 * tunnels get a random address and time out after ~60 min; re-run to refresh.
 *
 * POSIX only; Windows stub returns -1.
 */
#ifndef WLD_PINGGY_H
#define WLD_PINGGY_H 1

#include <stddef.h>

int wld_pinggy_autotunnel(int verbose, char *local_port_out, size_t lpcap,
                          char *pub_host_out, size_t phcap, int *pub_port_out);

/* Tear the ssh tunnel down (called before the process exits). */
void wld_pinggy_drain(int max_ms);

#endif /* WLD_PINGGY_H */
