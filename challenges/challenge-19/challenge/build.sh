#gcc -fno-stack-protector -O2 -no-pie -Wl,-z,noexecstack main.c -o text
gcc -fno-stack-protector -no-pie -Wl,-z,noexecstack main.c -o ezrop
