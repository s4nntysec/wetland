/*
 * wetland — purple-team lab module.
 *
 * Documented, reversible simulations of common evasion / persistence TTPs,
 * for exercising detections in an AUTHORIZED lab (Atomic-Red-Team style):
 * every technique logs what it did and where, embeds a WETLAND-LAB marker,
 * emits ATT&CK-mapped detection hints, and can be fully undone with
 * `wld lab uninstall`.
 *
 * This is NOT a stealth implant. The techniques are intentionally loud and
 * self-documenting so blue team can find them. Use only on systems you own
 * or are explicitly authorized to test.
 *
 * Entry point: dispatched from the client when argv[1] == "lab".
 * argv is the ORIGINAL process argv (so argv[0]'s memory can be rewritten).
 */
#ifndef WLD_LAB_H
#define WLD_LAB_H 1

int wld_lab_main(int argc, char **argv);

/* True if `arg` is a lab subcommand ("lab" or a technique name), so the client
 * can route both `wld lab persist` and the shortcut `wld persist`. */
int wld_lab_is_command(const char *arg);

#endif /* WLD_LAB_H */
