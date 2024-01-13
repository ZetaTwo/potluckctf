From rust:1.74-bookworm as builder

WORKDIR /app
COPY controller/Cargo.toml controller/Cargo.lock ./
COPY controller/ecsimple ./ecsimple
COPY controller/controller/Cargo.toml ./controller/Cargo.toml

# Build and cache the dependencies
RUN mkdir -p ./controller/src && echo "fn main() {}" > controller/src/main.rs
RUN cargo fetch
RUN cargo build --release
RUN rm controller/src/main.rs

# Copy the actual code files and build the application
COPY controller/controller/src ./controller/src/
# Update the file date
RUN touch controller/src/main.rs
RUN cargo build --release

FROM scratch as copy
COPY --from=builder /app/target/release/controller /controller

# STAGE2: create a slim image with the compiled binary
FROM debian:bookworm as runner

RUN set -ex;\
    apt-get update;\
    apt-get install -y libssl3

# Copy the binary from the builder stage
WORKDIR /app
COPY --from=builder /app/target/release/controller controller
COPY wait_for_can.sh .
COPY privkey .
COPY recipes.json . 
COPY flag1 flag
CMD ["./controller"]
