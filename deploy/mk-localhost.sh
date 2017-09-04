#!/bin/sh
docker build --no-cache -f deploy/Dockerfile -t minq --build-arg SERVERNAME=localhost .

