/* Native bounded helper with a double-forked, session-escaping descendant. */
#include <sys/wait.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
static void record(const char *dir, const char *name, int pid) {
    char path[4096]; snprintf(path, sizeof(path), "%s/%s", dir, name);
    FILE *f = fopen(path, "w"); if (!f) _exit(91);
    fprintf(f, "%d\n", pid); fclose(f);
}
static void hold(const char *dir) {
    char path[4096]; snprintf(path, sizeof(path), "%s/release-helper", dir);
    for (int i=0; i<2500 && access(path, F_OK); i++) usleep(10000);
    if (access(path, F_OK)) _exit(97);
}
int main(int argc, char **argv) {
    if (argc < 3 || strcmp(argv[2], "agent-bash-complete")) return 0;
    const char *d = getenv("AGE362_DIR"); if (!d) return 92;
    record(d, "worker", getppid()); record(d, "helper", getpid());
    pid_t child = fork(); if (child < 0) return 93;
    if (!child) {
        pid_t leaf = fork(); if (leaf < 0) _exit(94);
        if (leaf) _exit(0);
        if (setsid() < 0) _exit(95);
        signal(SIGTERM, SIG_IGN);
        record(d, "helper-leaf", getpid()); hold(d); _exit(0);
    }
    waitpid(child, NULL, 0);
    hold(d); record(d, "helper-finished", getpid()); return 0;
}
