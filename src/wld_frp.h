/*
 * wetland — native frp (fatedier/frp) reverse-tunnel client.
 *
 * Exposes a locally-running relay through a self-hosted frp server (frps), so a
 * listener behind NAT is reachable with no inbound port of its own.
 *
 * frp has NO public server — you run frps yourself on a public host. This client
 * speaks frp's control protocol natively (no external frpc binary), but to keep
 * it dependency-light it does NOT implement yamux or TLS, so the frps MUST be
 * configured with:
 *
 *     transport.tcpMux = false        # we open one work connection per stream
 *     # and must accept plaintext control connections (transport.tls.force=false,
 *     # which is the default)
 *     auth.token = "..."              # optional; set WLD_FRP_TOKEN to match
 *
 * Wire format (frp): each message is [1 type byte][int64 big-endian length]
 * [JSON payload]. Flow: Login -> LoginResp(run_id); NewProxy(tcp, remote_port)
 * -> NewProxyResp; then for each ReqWorkConn the client dials a fresh connection
 * to the frps port, sends NewWorkConn(run_id), reads StartWorkConn and proxies
 * it to the local target. Login auth key = md5hex(token + unix_timestamp).
 */
#ifndef WLD_FRP_H
#define WLD_FRP_H 1

#include <stddef.h>

#define WLD_FRP_DEFAULT_PORT  "7000"

/*
 * Bring up an embedded relay (127.0.0.1, ephemeral port) and expose it through
 * frps, in background threads that live for the process.
 *
 *   server_host     frps host (required; no public default)
 *   server_port     frps bindPort (NULL = 7000)
 *   token           auth.token, or NULL/"" if frps has none
 *   remote_port     desired public port on frps (0 = let frps choose)
 *   verbose         log detail
 *   local_port_out  <- embedded relay's local port (string)
 *   pub_host_out    <- public host for the connector (= server_host)
 *   pub_port_out    <- public port assigned by frps
 *
 * Blocks a few seconds for the tunnel. Returns 0 on success, -1 otherwise (an
 * embedded relay may still be running locally; *local_port_out is set when so).
 * POSIX only; Windows stub returns -1.
 */
int wld_frp_autotunnel(const char *server_host, const char *server_port,
                       const char *token, int remote_port, int verbose,
                       char *local_port_out, size_t lpcap,
                       char *pub_host_out, size_t phcap, int *pub_port_out);

/* Wait (<= max_ms) for in-flight proxied data to drain before exit. No-op if no
 * tunnel was established. */
void wld_frp_drain(int max_ms);

#endif /* WLD_FRP_H */
