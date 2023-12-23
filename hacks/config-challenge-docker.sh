#!/bin/sh
sudo gcloud auth configure-docker europe-west3-docker.pkg.dev
sudo docker pull europe-west3-docker.pkg.dev/potluck-ctf/challenge00-repository/challenge00:latest
