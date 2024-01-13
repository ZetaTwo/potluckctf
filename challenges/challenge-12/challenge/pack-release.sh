#!/bin/bash -e

cd "$(dirname "$0")"

export SOURCE_DATE_EPOCH="1563712200"
export GIT_REV="$(git rev-parse --short HEAD)"

git archive --format zip --output "out/src-$GIT_REV.zip" HEAD .

tar --sort=name \
      --mtime="@${SOURCE_DATE_EPOCH}" \
      --owner=0 --group=0 --numeric-owner \
      --transform='s,.*/,,' \
      -czf "out/challenge12-dist.tgz" \
      "challenge.c"

. check-build.sh

REPO=${REPO:-potluck-ctf-challenge-12}
TAG=${TAG:-r$GIT_REV}
docker buildx build --output type=oci,dest=- -t "$REPO:$TAG" . | zstd -c > out/oci-image.tar.zst
