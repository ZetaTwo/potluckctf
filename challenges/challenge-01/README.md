# Cake of Paranoia

The original image was built with the following steps:

- install arch linux into a VM
- install systemd-nspawn, socat, and debootstrap
- create a ubuntu chroot at /var/lib/machines/ubuntu
  - use `machinectl edit ubuntu` to add the configuration found in `ubuntu.nspawn`
  - launch: `machinectl start ubuntu`
  - enable at reboot: `machinectl enable ubuntu`
  - login: `machinectl shell root@ubuntu`
    - install docker in the traditional way: https://docs.docker.com/engine/install/ubuntu/
    - install openssh-server
    - build the Dockerfile located at `Dockerfile.alpine-inner`
    - launch the image to always restart, bind mount /root to /root, and expose 1337
- install `entrypoint` to `/usr/local/bin/entrypoint`
- install `serial-getty@ttyS0.service` to `/lib/systemd/system/serial-getty@ttyS0.service`
- enable `serial-getty@ttyS0.service`
- add your flag.txt :)

Your image is built!
Other items were added to the original image, but these ended up not being used for the actual solves, so they are not included.

The rootfs tarfile distributed originally with the challenge was the VM's image mounted and the flag.txt deleted.

## Infrastructure Considerations

The QEMU instance takes about 1G of memory per instance.
The instances are isolated from each other with `-snapshot`, so contestants can't interfere/inspect each other's solutions.

The connection to the QEMU instance is over serial, with socat being used to connect to the innermost machine.
You can visualise a connection as:

```
contestant
    |
    |
    v
socat (challenge container)
    |
    | // qemu spawned per connection
    v
qemu serial socket
    |
    |
    v
socat (VM)
    |
    |
    v
socat (docker container port bind)
    |
    |
    v
alpine shell (innermost docker container)
```

The docker container for the challenge should be spawned with `--privileged`.
If the hosting infrastructure does not have KVM, the challenge should be modified to not use KVM, though this is significantly slower and more intensive in memory.

## Solve Explanation

This is a two-layer escape challenge.

### Layer 1

Layer one is a docker container, which has the /root directory bind-mounted to the docker host.
The solution is simple: generate an SSH key and add it to authorized_keys, then ssh to the docker host.
We upload dropbear to the server to give us an ssh client, as there is no network connectivity on the device.

### Layer 2

Layer two is a bit more complicated.
The docker host is a systemd-nspawn container, which has been configured to run docker.
Because systemd-nspawn is not a very secure containerisation platform, it does not have certain restrictions.
For example, we can remount proc to access kernel configuration.
Then, we overwrite the core_pattern to inject commands into the parent; namely, we copy the flag from /flag.txt to /var/lib/machines/ubuntu/flag.txt (/flag.txt to us locally).
By triggering a segfault by dereferencing a null pointer, the core is dumped and the flag is written to our /flag.txt.
Read and win.
