#!/bin/sh

export FLAG="$(cat /home/ctf/flag.txt)"
/etc/init.d/xinetd start;
sleep infinity;