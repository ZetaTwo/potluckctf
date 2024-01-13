# cookmaster - Potluck CTF 2023

Starting the interface from the root folder with `docker compose up`
should set everything up out of the box, and open a web interface on
localhost at port 31337. You might have to `modprobe vcan` (e.g. on
Ubuntu this requires you installing extra kernel modules) and some
shenanigans for running the docker-in-docker setup. 

## Exploits

Make sure to compile the `randgen` Rust project first (in release
mode), this is needed for the crypto exploit to work. 
