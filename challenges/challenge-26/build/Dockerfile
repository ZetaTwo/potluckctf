FROM ubuntu:23.10

RUN apt update && apt install build-essential -y

COPY chal.c /chal.c
RUN cc chal.c -o chal

