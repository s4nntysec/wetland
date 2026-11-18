/*
 * wetland — one tunnelled session (relay/auto-tunnel + rendezvous + handshake +
 * greeting + serve), factored out of the client's main() so the lab module can
 * also run a listener (`wld lab <tech> -l/-i/-e`).
 *
 * Assumes wld_crypto_init() and wld_net_startup() have already run, and that any
 * process masquerade (-M) has already been applied by the caller. Returns 0 on
 * success, non-zero on failure (fatal setup errors exit via die()).
 */
#ifndef WLD_SESSION_H
#define WLD_SESSION_H 1

struct wld_session_opts {
	const char *secret;        /* required                              */
	int   listen_mode;         /* -l                                    */
	int   interactive;         /* -i                                    */
	const char *cmd;           /* -e command, or NULL                   */
	int   wait_flag;           /* -w                                    */
	long  epoch_secs;          /* -R, 0 = static address                */
	const char *host;          /* relay host (NULL -> default/auto)     */
	const char *port;          /* relay port (NULL -> default)          */
	int   use_pool;            /* -x                                    */
	int   relay_specified;     /* host came from -H/-x/env              */
};

int wld_run_session(const struct wld_session_opts *o);

/*
 * Full client entry (flag parsing, init, secret, -M, session). `argv` is a
 * client-style vector (argv[0] + flags). Used by the lab module to serve a
 * listener alongside a technique.
 */
int wld_client_run(int argc, char **argv);

#endif /* WLD_SESSION_H */
