/*
 * wetland - Windows NAT port-mapping backend (NAT-PMP + UPnP-IGD).
 *
 * Opens a NAT'd listener to the internet with NO relay, NO separate server and
 * NO third-party service, by asking the local router to forward a port:
 *   1) start the embedded relay bound on all interfaces,
 *   2) map its port on the router via NAT-PMP (RFC 6886), else UPnP-IGD,
 *   3) report the public host:port the other side should dial.
 *
 * Windows-only on purpose (the POSIX build keeps the pinggy tunnel). On POSIX
 * these are no-op stubs so the shared tunnel selector links everywhere.
 */
#ifndef WLD_NATMAP_H
#define WLD_NATMAP_H 1

#include <stddef.h>

/*
 * Returns 0 on success (port mapped; outputs filled), -1 otherwise - on failure
 * the embedded relay it may have started is stopped again, so the caller can
 * fall through to a tunnel backend. local_port_out = the embedded relay's local
 * port (dial 127.0.0.1:local); pub_host_out/pub_port_out = the public endpoint.
 */
int wld_natmap_open(int verbose, char *local_port_out, size_t lpcap,
                    char *pub_host_out, size_t phcap, int *pub_port_out);

/* Remove the router mapping and stop the embedded relay (call before exit).
 * No-op if wld_natmap_open was not the backend that succeeded. */
void wld_natmap_drain(int max_ms);

#endif /* WLD_NATMAP_H */
