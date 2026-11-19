/* Native stand-in so the service controller can verify /proc/PID/exe. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int main(int argc, char **argv)
{
    if (argc > 1 && strcmp(argv[1], "-dry-run") == 0)
        return 0;
    if (argc == 2 && strcmp(argv[1], "-startup-state-protocol") == 0) {
#ifdef LEGACY_STARTUP
        fputs("flag provided but not defined: -startup-state-protocol\n", stderr);
        return 2;
#else
        puts("1");
        return 0;
#endif
    }

    /* Match a legacy CLI: unknown read-only flags must not start a daemon. */
    for (int i = 1; i < argc; i += 2) {
        if (i + 1 >= argc ||
            (strcmp(argv[i], "-config") != 0 &&
             strcmp(argv[i], "-rule-sets") != 0 &&
             strcmp(argv[i], "-iptables") != 0 &&
             strcmp(argv[i], "-iptables-restore") != 0))
            return 2;
    }

#ifdef FAIL_START
    return 1;
#else
    const char *log = getenv("FIXTURE_PIDS");
    if (log == NULL)
        return 1;
    FILE *pids = fopen(log, "a");
    if (pids == NULL)
        return 1;
    fprintf(pids, "%ld\n", (long)getpid());
    if (fclose(pids) != 0)
        return 1;
#ifndef LEGACY_STARTUP
    const char *mode = getenv("FIXTURE_STARTUP_STATE");
    if (mode != NULL) {
        const char *path = getenv("KEENPROXY_STARTUP_STATE_FILE");
        if (path == NULL)
            return 1;
        FILE *state = fopen(path, "w");
        if (state == NULL)
            return 1;
        long pid = getpid();
        if (strcmp(mode, "wrong-pid") == 0) {
            pid++;
            mode = "active";
        }
        fprintf(state, "%s %ld\n", mode, pid);
        if (fclose(state) != 0)
            return 1;
    }
#endif
    for (;;)
        pause();
#endif
}
