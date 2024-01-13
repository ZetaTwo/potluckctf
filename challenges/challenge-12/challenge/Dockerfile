FROM debian:unstable-20231218 AS build-qemu

RUN apt-get update && \
    apt-get install -y build-essential git python3 ninja-build pkg-config musl-tools
# 7ff6ece8ab415ed5c6c34b35cafeeee186f95d1f: head of branch "qemu-6.2.0" on 2023/12/21
RUN git init --initial-branch dummy b && \
    git -C b remote add origin https://github.com/openeuler-mirror/qemu.git && \
    git -C b fetch --depth 1 origin 7ff6ece8ab415ed5c6c34b35cafeeee186f95d1f && \
    git -C b checkout FETCH_HEAD
RUN apt-get install -y libglib2.0-dev meson
COPY 0001-linux-user-sw64-fix-syscall-emulation.patch /tmp
RUN git -C /b apply /tmp/0001-linux-user-sw64-fix-syscall-emulation.patch
WORKDIR /b
# sw64 code of course has warnings on "modern" compilers (anything other than openEuler ships, it 
# seems); --enable-tools is required because of a BUILD file defect: it does not build 
# util/qemu-timer.c if system and tools are both disabled.
RUN ./configure --extra-cflags="-Wno-error" --target-list=sw64-linux-user --enable-tools --static && \
    make -j$(nproc) && \
    make install
COPY launcher.c /tmp/launcher.c
RUN musl-gcc -Os -static -s -o /tmp/launcher /tmp/launcher.c

FROM debian:unstable-20231218 AS build-challenge
RUN mkdir /usr/sw
ADD swgcc710-cross-6b-9916.tar.gz /usr/sw
ENV PATH=$PATH:/usr/sw/swgcc710-cross-6b-9916/usr/bin
COPY challenge.c /challenge.c
RUN sw_64sw6b-sunway-linux-gnu-gcc -Os -s -Wl,-dynamic-linker,/lib/ld-linux.so.2 \
    -o /challenge /challenge.c

FROM pwn.red/jail@sha256:ee52ad5fd6cfed7fd8ea30b09792a6656045dd015f9bef4edbbfa2c6e672c28c
ARG FLAG_NAME=flag_62291540-8131-4648-8dc8-38a45d8ebbf7

RUN mkdir -p /srv/proc /srv/dev /srv/usr/bin /srv/app
COPY --from=build-qemu /usr/local/bin/qemu-sw64 /srv/usr/bin/qemu-sw64
COPY --from=build-qemu /tmp/launcher /srv/app/run
COPY --from=build-challenge /usr/sw/swgcc710-cross-6b-9916/lib /srv/lib
COPY --from=build-challenge /challenge /srv/usr/bin/challenge
COPY flag /srv/${FLAG_NAME}

ENV JAIL_MEM=32M
