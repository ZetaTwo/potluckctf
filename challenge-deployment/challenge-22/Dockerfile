FROM sekurbut
RUN apk add --no-cache socat htop
ENTRYPOINT [ "socat", "tcp-l:1337,fork,reuseaddr", "exec:'qemu-system-arm -M microbit -device loader,file=flagloader.hex -nographic -serial stdio -monitor /dev/null'" ]
EXPOSE 1337
