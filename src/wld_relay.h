/*
 * wetland — embeddable relay core.
 *
 * The rendezvous server loop, factored out of the `wetland-relay` binary so the
 * client can also run a relay in-process (see the frp auto-tunnel in
 * client.c). Single-threaded, poll(2) based; one instance per process.
 */
#ifndef WLD_RELAY_H
#define WLD_RELAY_H 1

#include <signal.h>

/*
 * Bind host:port and serve rendezvous until *stop becomes non-zero.
 *   host          bind address, NULL = all interfaces
 *   port          port string; "0" picks an ephemeral port
 *   verbose       enable the per-pair log lines
 *   announce      print a "listening on host:port" banner to stderr
 *   stop          caller-owned stop flag (must be non-NULL)
 *   assigned_port if non-NULL, receives the actual bound TCP port
 * Returns 0 on clean shutdown, -1 on a fatal setup error.
 */
int wld_relay_serve(const char *host, const char *port, int verbose,
                    int announce, volatile sig_atomic_t *stop,
                    int *assigned_port);

/* Number of live connections the (single, in-process) relay currently holds.
 * Used by embedded tunnels to wait for in-flight data to drain before exit. */
int wld_relay_live_conns(void);

#endif /* WLD_RELAY_H */
