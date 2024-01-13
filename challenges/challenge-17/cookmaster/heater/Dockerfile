FROM gcc:13.2.0 as builder

ENV DEBIAN_FRONTEND noninteractive
RUN apt-get update && \
    apt-get -y install gcc make openssl && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY heater/Makefile .
COPY heater/heater.c .
RUN make

FROM scratch as copy
COPY --from=builder /app/heater /heater


FROM debian:bookworm-20231218 as runner
ENV DEBIAN_FRONTEND noninteractive
RUN apt-get update && \
    apt-get -y install openssl && \
    rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY --from=builder /app/heater heater
COPY flag2 flag
COPY wait_for_can.sh .
COPY pubkey .

CMD /app/wait_for_can.sh; ./heater
