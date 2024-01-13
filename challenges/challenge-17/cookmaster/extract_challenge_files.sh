#!/usr/bin/bash

docker buildx build --target copy -o out --file controller/Dockerfile .
docker buildx build --target copy -o out --file heater/Dockerfile .
