FROM rust:buster

RUN apt-get update -y && apt-get install -y xinetd

RUN useradd -m ctf

WORKDIR /home/ctf
COPY flag.txt Cargo.toml Cargo.lock ./
COPY src ./src
RUN cargo build --release && \
    mv target/release/abc . && \
    rm -rf target src Cargo.*

COPY ./ctf.xinetd /etc/xinetd.d/ctf
COPY ./start.sh /start.sh
RUN echo "Blocked by xinetd" > /etc/banner_fail

RUN chmod +x /start.sh

RUN chown -R root:ctf /home/ctf && \
    chmod -R 750 /home/ctf && \
    chmod 740 /home/ctf/flag.txt

CMD ["/start.sh"]

EXPOSE 9999