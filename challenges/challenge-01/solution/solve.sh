#!/bin/bash

# read the pow and then execute the actual solver
(head -n 1; ./solve-helper.sh; sleep 1) | socat - tcp-connect:localhost:5000
