/*
 * wetland - bore-style reverse tunnel client.
 *
 * Speaks the control protocol of ekzhang/bore (https://github.com/ekzhang/bore)
 * so a listener behind NAT can expose a locally-running relay through a public
 * bore server (e.g. bore.pub) with no inbound port of its own.
 *
 * Wire protocol (from bore's shared.rs): a TCP control connection to
 * CONTROL_PORT, messages are JSON objects separated by a single NUL byte
 * (AnyDelimiterCodec, 256-byte frames). Client sends {"Hello":port}; server
 * replies {"Hello":public_port}. Thereafter the server sends "Heartbeat" and
 * {"Connection":"<uuid>"}; for each Connection the client opens a fresh control
 * connection, sends {"Accept":"<uuid>"} and proxies it to the local target.
 *
 * bore.pub requires no secret, so the optional Challenge/Authenticate exchange
 * is not implemented (a Challenge is reported as an error).
 */
#ifndef WLD_BORE_H
#define WLD_BORE_H 1

#include <stddef.h>

#define WLD_BORE_DEFAULT_HOST  "bore.pub"
#define WLD_BORE_CONTROL_PORT  "7835"

/*
 * Bring up an embedded relay (on 127.0.0.1, ephemeral port) and a bore reverse
 * tunnel exposing it on `bore_host`, in background threads that run for the
 * life of the process.
 *
 *   bore_host       public bore server (NULL = bore.pub)
 *   requested_port  desired public port on the bore server (0 = let it choose)
 *   verbose         log tunnel/relay detail
 *   local_port_out  <- the embedded relay's local port, as a string (dial this)
 *   pub_host_out    <- the public host to give the connector
 *   pub_port_out    <- the public port assigned by the bore server
 *
 * Blocks up to a few seconds for the tunnel to come up. Returns 0 on success
 * (outputs filled), -1 if the tunnel could not be established (an embedded relay
 * may still be running locally; *local_port_out is filled when it is).
 *
 * POSIX only; on Windows this is a stub that returns -1.
 */
int wld_bore_autotunnel(const char *bore_host, int requested_port, int verbose,
                        char *local_port_out, size_t lpcap,
                        char *pub_host_out, size_t phcap,
                        int *pub_port_out);

/*
 * Block until in-flight proxied data has drained (no active proxy connection),
 * capped at max_ms. Call before exiting a process that used wld_bore_autotunnel,
 * so a one-shot transfer the embedded relay is still forwarding is not cut off.
 * No-op if no tunnel was established.
 */
void wld_bore_drain(int max_ms);

#endif /* WLD_BORE_H */
