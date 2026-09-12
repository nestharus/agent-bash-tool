/* Native bounded helper with independently settled session-escaping descendant. */
#include <sys/wait.h>
#include <signal.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
static int signal_fd = -1;
static void observed_term(int sig) {
    (void)sig;
    if (write(signal_fd, "T", 1) != 1) _exit(98);
}
static void observe(const char *dir, const char *name) {
    char path[4096]; snprintf(path, sizeof(path), "%s/%s", dir, name);
    if (signal_fd >= 0) close(signal_fd);
    signal_fd = open(path, O_WRONLY | O_CREAT | O_APPEND, 0600);
    if (signal_fd < 0 || signal(SIGTERM, observed_term) == SIG_ERR) _exit(96);
}
static void record(const char *dir, const char *name, int pid) {
    char path[4096]; snprintf(path, sizeof(path), "%s/%s", dir, name);
    FILE *f = fopen(path, "w"); if (!f) _exit(91);
    fprintf(f, "%d\n", pid); fclose(f);
}
static void hold(const char *dir, const char *release) {
    char path[4096]; snprintf(path, sizeof(path), "%s/%s", dir, release);
    for (int i=0; i<2500 && access(path, F_OK); i++) usleep(10000);
    if (access(path, F_OK)) _exit(97);
}
int main(int argc, char **argv) {
    if (argc < 3 || strcmp(argv[2], "agent-bash-complete")) return 0;
    const char *d = getenv("AGE362_DIR"); if (!d) return 92;
    observe(d, "helper-signals");
    record(d, "worker", getppid()); record(d, "helper", getpid());
    pid_t child = fork(); if (child < 0) return 93;
    if (!child) {
        pid_t leaf = fork(); if (leaf < 0) _exit(94);
        if (leaf) _exit(0);
        if (setsid() < 0) _exit(95);
        observe(d, "leaf-signals");
        record(d, "helper-leaf", getpid()); hold(d, "release-leaf");
        record(d, "leaf-finished", getpid()); _exit(0);
    }
    waitpid(child, NULL, 0);
    hold(d, "release-helper"); record(d, "helper-finished", getpid()); return 0;
}
