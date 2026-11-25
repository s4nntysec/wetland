/*
 * wetland - zero-config tunnel selector.
 *
 * Shared by the listener (`-l`) and the lab module (`wld lab --tunnel`): brings
 * up the embedded relay and a public reverse tunnel, choosing the backend from
 * the environment - WLD_FRP_SERVER -> frp; WLD_BORE_HOST -> bore; else pinggy.
 */
#ifndef WLD_AUTOTUNNEL_H
#define WLD_AUTOTUNNEL_H 1

#include <stddef.h>

/*
 * Open the tunnel. Prints the "no relay configured - ... tunnel..." line.
 * Fills local_port (the embedded relay's loopback port), pub_host/pub_port (the
 * public endpoint for the connector) and, if the backend expires (pinggy),
 * *expiry_secs (>0). Returns 0 on success, -1 otherwise (local_port may still
 * be set if the embedded relay came up). `secret` seeds the derived remote port
 * for frp/bore.
 */
int wld_open_tunnel(const char *secret, int verbose,
                    char *local_port, size_t lpc,
                    char *pub_host, size_t phc, int *pub_port,
                    long *expiry_secs);

/* Drain/stop whichever tunnel backend is active (call before exit). */
void wld_tunnel_drain_all(int max_ms);

#endif /* WLD_AUTOTUNNEL_H */
