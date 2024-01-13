FROM ubuntu:20.04@sha256:9b8dec3bf938bc80fbe758d856e96fdfab5f56c39d44b0cff351e847bb1b01ea
ENV DEBIAN_FRONTEND noninteractive

RUN apt update && apt install -y socat

WORKDIR /app

COPY ./ezrop .
COPY ./flag.txt .


RUN chmod +x ezrop

RUN chown -R root:root /app/*
RUN chmod -R o-w /app/*
RUN chown -R root:root /app/flag.txt
RUN chmod -R o-w /app/flag.txt

RUN useradd ctf
USER ctf

ENTRYPOINT socat TCP4-LISTEN:2727,fork,reuseaddr EXEC:/app/ezrop
