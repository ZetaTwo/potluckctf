FROM ubuntu:23.10

RUN apt update && apt install socat -y

COPY chal /chal
COPY flag.txt /flag.txt

CMD socat tcp-listen:1337,reuseaddr,fork, exec:./chal
