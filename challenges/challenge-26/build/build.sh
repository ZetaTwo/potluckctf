#!/bin/sh
docker build -t tamagoyaki . 

rm -rf out
mkdir out

id=$(docker create tamagoyaki)
docker cp $id:/chal out/
docker cp -L $id:/lib/x86_64-linux-gnu/libc.so.6 out/
docker cp -L $id:/lib64/ld-linux-x86-64.so.2 out/
docker rm -v $id


echo "potluck{ptr_pr0t_i5_c00l_n_411_bu7_d03s_1t_wrk?}" > out/flag.txt
