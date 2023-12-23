#!/bin/sh

# gcloud compute start-iap-tunnel INSTANCE_NAME INSTANCE_PORT --local-host-port=localhost:LOCAL_PORT --zone=ZONE
INSTANCE_NAME="$1"

echo "Tunneling to localhost:31337 -> $INSTANCE_NAME:31337"
gcloud compute start-iap-tunnel $1 31337 --local-host-port=localhost:31337 --iap-tunnel-disable-connection-check --zone europe-west3-b
