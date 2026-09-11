/* Tiny opaque native delivery helper: reports version identity and request routing. */
#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
int main(int argc, char **argv) {
    struct stat st;
    if (stat("/proc/self/exe", &st)) return 91;
    const char *path = getenv("IMAGE_FIXTURE_LOG");
    if (path) {
        FILE *f = fopen(path, "a");
        if (!f) return 92;
        fprintf(f, "%lu %s %s\n", (unsigned long)st.st_ino,
                argc > 2 ? argv[2] : "none",
                getenv("OULIPOLY_COMPLETION_REGISTRATION_AUTHORITY") ? "authority" : "no-authority");
        fclose(f);
    }
    const char *hold = getenv("IMAGE_FIXTURE_HOLD");
    if (hold && argc > 2 && !strcmp(argv[2], "agent-bash-complete")) {
        char marker[4096]; snprintf(marker, sizeof(marker), "%s.admitted", hold);
        int fd = open(marker, O_WRONLY | O_CREAT, 0600);
        if (fd < 0) return 96;
        close(fd);
        for (int i = 0; i < 1000 && access(hold, F_OK); i++) usleep(10000);
        if (access(hold, F_OK)) return 97;
    }
    /* A wake-like self-exec pins the same image after the original custodian dies. */
    if (argc == 3 && !strcmp(argv[1], "self-exec")) {
        int fd = open("/proc/self/exe", O_RDONLY);
        if (fd < 0) return 93;
        char path[64]; snprintf(path, sizeof(path), "/proc/self/fd/%d", fd);
        execl(path, path, "held", argv[2], NULL);
        return 94;
    }
    if (argc == 3 && !strcmp(argv[1], "held")) {
        printf("%lu\n", (unsigned long)st.st_ino); fflush(stdout);
        char c; return read(0, &c, 1) == 1 ? 0 : 95;
    }
    return 0;
}
