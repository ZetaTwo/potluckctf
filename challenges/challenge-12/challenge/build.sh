#!/bin/bash -e

. check-build.sh

REPO=${REPO:-potluck-ctf-challenge-12}
TAG=${TAG:-latest}

docker build -t "$REPO:$TAG" .
