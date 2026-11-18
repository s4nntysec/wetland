/*
 * wetland — encrypted transport pump
 *
 * Relays bytes between a local endpoint (a read fd + a write fd, which may be
 * the same, e.g. a socket or a PTY master) and the end-to-end tunnel socket,
 * sealing/opening ChaCha20-Poly1305 records in both directions.
 */
#ifndef WLD_TUNNEL_H
#define WLD_TUNNEL_H 1

#include "wld_crypto.h"

/*
 * Pump until either side closes. `tun_fd` carries the encrypted stream;
 * `local_rd`/`local_wr` the cleartext (may be equal). All three are switched
 * to non-blocking internally. Honors half-close: local EOF -> flush -> signal
 * peer; peer EOF -> flush -> return. Returns 0 on clean shutdown, -1 on a
 * transport/authentication error.
 */
int wld_pump(int tun_fd, int local_rd, int local_wr, wld_session *sess);

/*
 * One-way post-handshake greeting, done on the blocking socket before wld_pump.
 * The responder (listener) sends exactly one record; the initiator (connector)
 * receives exactly one. Both advance their counters by one, keeping the pump in
 * sync. `msg` is a short text note (may be empty). Return 0 on success, -1 on
 * I/O or authentication error. These MUST be called in matched pairs.
 */
int wld_tunnel_send_greeting(int fd, wld_session *sess, const char *msg);
int wld_tunnel_recv_greeting(int fd, wld_session *sess, char *out, size_t cap);

#endif /* WLD_TUNNEL_H */
