#!/usr/bin/env bash
set -x

cd /app;
while true; do
    su app -c "node main-server.js";
done;