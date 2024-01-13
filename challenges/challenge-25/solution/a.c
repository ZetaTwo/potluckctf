#define _GNU_SOURCE
#include <err.h>
#include <stdio.h>
#include <unistd.h>

int main(void) {
    setbuf(stdout, NULL);
    setbuf(stderr, NULL);

    printf("uid: %d, euid: %d\n", getuid(), geteuid());

    int p = fork();
    if (p < 0) {
        err(1, "fork");
    } else if (p == 0) {
        printf("child waiting: %d\n", getpid());
        char c = 0;
        ssize_t x = read(1001, &c, 1);
        printf("GOT: %ld %#hhx\n", x, c);
        return 0;
    }

    printf("HELLO: %d\n", getpid());

    return 0;
}
