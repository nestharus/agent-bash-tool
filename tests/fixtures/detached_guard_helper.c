#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <linux/prctl.h>
#include <signal.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <unistd.h>

#ifndef __WALL
#define __WALL 0x40000000
#endif

#ifndef PTRACE_O_TRACESYSGOOD
#define PTRACE_O_TRACESYSGOOD 0x00000001
#endif

#ifndef PR_SET_PTRACER
#define PR_SET_PTRACER 0x59616d61
#endif

static const char *g_bin;
static const char *g_state_home;
static const char *g_stdout_path;
static const char *g_stderr_path;
static const char *g_rc_path;
static const char *g_ppid_trace_path;

static void write_text(const char *path, const char *text) {
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
    if (fd < 0) {
        _exit(120);
    }
    size_t len = strlen(text);
    if (write(fd, text, len) != (ssize_t)len) {
        _exit(121);
    }
    close(fd);
}

static void write_int_file(const char *path, int value) {
    char buf[64];
    int len = snprintf(buf, sizeof(buf), "%d\n", value);
    if (len <= 0 || len >= (int)sizeof(buf)) {
        _exit(122);
    }
    write_text(path, buf);
}

static void write_ppid_trace(long startup_ppid, long reparented_ppid) {
    char buf[128];
    int len = snprintf(buf, sizeof(buf), "%ld\n%ld\n", startup_ppid, reparented_ppid);
    if (len <= 0 || len >= (int)sizeof(buf)) {
        _exit(123);
    }
    write_text(g_ppid_trace_path, buf);
}

static void helper_error(const char *message) {
    write_text(g_rc_path, message);
    _exit(124);
}

static void redirect_to(const char *path, int target_fd) {
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
    if (fd < 0) {
        helper_error("open-redirect-failed\n");
    }
    if (dup2(fd, target_fd) < 0) {
        helper_error("dup2-failed\n");
    }
    close(fd);
}

static void exec_agent_bash(int ready_write, int release_read, pid_t tracer_pid) {
    (void)prctl(PR_SET_PTRACER, (unsigned long)tracer_pid, 0, 0, 0);
    char ready = 'r';
    if (write(ready_write, &ready, 1) != 1) {
        helper_error("ready-pipe-write-failed\n");
    }
    close(ready_write);
    char release = 0;
    if (read(release_read, &release, 1) != 1) {
        helper_error("release-pipe-read-failed\n");
    }
    close(release_read);
    redirect_to(g_stdout_path, STDOUT_FILENO);
    redirect_to(g_stderr_path, STDERR_FILENO);
    setenv("XDG_STATE_HOME", g_state_home, 1);
    setenv("AGENT_BASH_AGENT_RUNNER_BIN", "/bin/true", 1);
    char *const argv[] = {(char *)g_bin, "list", "--json", NULL};
    execv(g_bin, argv);
    perror("execv");
    _exit(127);
}

static pid_t start_agent_parent(int child_ready[2], int child_release[2], int parent_exit[2], pid_t *parent_pid) {
    int child_pid_pipe[2];
    if (pipe2(child_pid_pipe, O_CLOEXEC) != 0) {
        helper_error("child-pid-pipe-failed\n");
    }
    pid_t parent = fork();
    if (parent < 0) {
        helper_error("parent-fork-failed\n");
    }
    if (parent == 0) {
        close(child_ready[0]);
        close(child_release[1]);
        close(parent_exit[1]);
        close(child_pid_pipe[0]);
        pid_t tracer_pid = getppid();
        pid_t child = fork();
        if (child < 0) {
            _exit(125);
        }
        if (child == 0) {
            close(parent_exit[0]);
            close(child_pid_pipe[1]);
            exec_agent_bash(child_ready[1], child_release[0], tracer_pid);
        }
        if (write(child_pid_pipe[1], &child, sizeof(child)) != (ssize_t)sizeof(child)) {
            _exit(126);
        }
        close(child_pid_pipe[1]);
        char release_parent = 0;
        if (read(parent_exit[0], &release_parent, 1) < 0) {
            _exit(127);
        }
        _exit(0);
    }
    close(child_ready[1]);
    close(child_release[0]);
    close(parent_exit[0]);
    close(child_pid_pipe[1]);
    *parent_pid = parent;
    pid_t child = -1;
    if (read(child_pid_pipe[0], &child, sizeof(child)) != (ssize_t)sizeof(child)) {
        helper_error("child-pid-read-failed\n");
    }
    close(child_pid_pipe[0]);
    return child;
}

static long syscall_return_value(pid_t child) {
#if defined(__x86_64__)
    struct user_regs_struct regs;
    if (ptrace(PTRACE_GETREGS, child, NULL, &regs) != 0) {
        helper_error("ptrace-getregs-failed\n");
    }
    return (long)regs.rax;
#else
    helper_error("unsupported-arch\n");
#endif
}

static long syscall_number(pid_t child) {
#if defined(__x86_64__)
    struct user_regs_struct regs;
    if (ptrace(PTRACE_GETREGS, child, NULL, &regs) != 0) {
        helper_error("ptrace-getregs-failed\n");
    }
    return (long)regs.orig_rax;
#else
    helper_error("unsupported-arch\n");
#endif
}

static void continue_syscall(pid_t child) {
    if (ptrace(PTRACE_SYSCALL, child, NULL, NULL) != 0) {
        helper_error("ptrace-syscall-failed\n");
    }
}

static void trace_child_to_exit(pid_t child, pid_t parent, int child_ready_read, int child_release_write, int parent_exit_write) {
    char ready = 0;
    if (read(child_ready_read, &ready, 1) != 1) {
        helper_error("ready-pipe-read-failed\n");
    }
    close(child_ready_read);
    if (ptrace(PTRACE_ATTACH, child, NULL, NULL) != 0) {
        helper_error("ptrace-attach-failed\n");
    }
    int status = 0;
    if (waitpid(child, &status, __WALL) < 0) {
        helper_error("ptrace-attach-wait-failed\n");
    }
    if (ptrace(PTRACE_SETOPTIONS, child, NULL, (void *)(uintptr_t)PTRACE_O_TRACESYSGOOD) != 0) {
        helper_error("ptrace-setoptions-failed\n");
    }
    char release = 'x';
    if (write(child_release_write, &release, 1) != 1) {
        helper_error("release-pipe-write-failed\n");
    }
    close(child_release_write);
    int in_syscall = 0;
    int getppid_seen = 0;
    long startup_ppid = -1;
    long reparented_ppid = -1;
    continue_syscall(child);
    for (;;) {
        if (waitpid(child, &status, __WALL) < 0) {
            if (errno == EINTR) {
                continue;
            }
            helper_error("trace-wait-failed\n");
        }
        if (WIFEXITED(status)) {
            write_ppid_trace(startup_ppid, reparented_ppid);
            write_int_file(g_rc_path, WEXITSTATUS(status));
            return;
        }
        if (WIFSIGNALED(status)) {
            write_ppid_trace(startup_ppid, reparented_ppid);
            write_int_file(g_rc_path, 128 + WTERMSIG(status));
            return;
        }
        if (WIFSTOPPED(status) && (WSTOPSIG(status) & 0x80) != 0) {
            long number = syscall_number(child);
            if (number == SYS_getppid) {
                if (in_syscall) {
                    long value = syscall_return_value(child);
                    if (getppid_seen == 0) {
                        startup_ppid = value;
                        char exit_parent = 'p';
                        if (write(parent_exit_write, &exit_parent, 1) != 1) {
                            helper_error("parent-exit-write-failed\n");
                        }
                        close(parent_exit_write);
                        int parent_status = 0;
                        while (waitpid(parent, &parent_status, 0) < 0) {
                            if (errno != EINTR) {
                                helper_error("parent-wait-failed\n");
                            }
                        }
                        if (!WIFEXITED(parent_status)) {
                            helper_error("parent-exit-failed\n");
                        }
                    } else if (getppid_seen == 1) {
                        reparented_ppid = value;
                    }
                    getppid_seen++;
                }
                in_syscall = !in_syscall;
            }
        }
        continue_syscall(child);
    }
}

static void detached_monitor(void) {
    if (prctl(PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) != 0) {
        helper_error("subreaper-setup-failed\n");
    }
    int child_ready[2];
    int child_release[2];
    int parent_exit[2];
    if (pipe2(child_ready, O_CLOEXEC) != 0 || pipe2(child_release, O_CLOEXEC) != 0 || pipe2(parent_exit, O_CLOEXEC) != 0) {
        helper_error("pipe-failed\n");
    }
    pid_t parent = -1;
    pid_t child = start_agent_parent(child_ready, child_release, parent_exit, &parent);
    trace_child_to_exit(child, parent, child_ready[0], child_release[1], parent_exit[1]);
    _exit(0);
}

int main(int argc, char **argv) {
    if (argc != 7) {
        return 2;
    }
    g_bin = argv[1];
    g_state_home = argv[2];
    g_stdout_path = argv[3];
    g_stderr_path = argv[4];
    g_rc_path = argv[5];
    g_ppid_trace_path = argv[6];

    pid_t pid = fork();
    if (pid < 0) {
        return 3;
    }
    if (pid > 0) {
        return 0;
    }
    detached_monitor();
}
