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

#endif /* WLD_TUNNEL_H */
