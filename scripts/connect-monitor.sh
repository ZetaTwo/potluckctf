#!/bin/sh
gcloud compute ssh --tunnel-through-iap monitor-a -- -L9000:localhost:9000 -L3000:localhost:3000
