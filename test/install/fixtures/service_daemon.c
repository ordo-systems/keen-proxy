/* Native stand-in so the service controller can verify /proc/PID/exe. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int main(int argc, char **argv)
{
    if (argc > 1 && strcmp(argv[1], "-dry-run") == 0)
        return 0;

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
    for (;;)
        pause();
#endif
}
