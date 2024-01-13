#include <unistd.h>

int main(int argc, char* argv[], char* envp[]) {
  return execl("/usr/bin/qemu-sw64", "/usr/bin/qemu-sw64", "/usr/bin/challenge", NULL);
}