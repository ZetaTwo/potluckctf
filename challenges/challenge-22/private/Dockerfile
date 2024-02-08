ARG TOOLCHAIN_VERSION=13.2.rel1
ARG FLAG1=potluck{duMp1n6_th3_b0o7l0ad3r_4_fuN_&_pr0f1t}
ARG FLAG2=potluck{y_i5_s3curb007_s0_h4rD}
FROM ubuntu:latest as fetch-toolchain
ARG TOOLCHAIN_VERSION

RUN apt-get update && apt-get -y install wget xz-utils
RUN wget -O arm-toolchain.tar.xz https://developer.arm.com/-/media/Files/downloads/gnu/${TOOLCHAIN_VERSION}/binrel/arm-gnu-toolchain-${TOOLCHAIN_VERSION}-x86_64-arm-none-eabi.tar.xz
RUN tar -C /usr/local --strip-components=1 -xvf ../arm-toolchain.tar.xz

FROM ubuntu as builder
COPY --from=fetch-toolchain /usr/local /usr/local
RUN apt-get update && apt-get -y install make xxd python3 python3-pyelftools
WORKDIR  /build
ADD *.c *.h Makefile *.ld build_app_hash.py /build/
ADD printf /build/printf/
ARG FLAG1
ARG FLAG2
RUN make FLAG1="${FLAG1}" FLAG2="${FLAG2}" flagloader.hex

FROM alpine
RUN apk add --no-cache qemu-system-arm
WORKDIR /chall
COPY --from=builder /build/flagloader.hex /chall/
EXPOSE 1234
ENTRYPOINT [ "qemu-system-arm", "-M", "microbit", "-device", "loader,file=flagloader.hex", "-nographic", "-serial", "stdio", "-monitor", "/dev/null" ]
# Run with -S -s and expose port 1234 for easy debugging