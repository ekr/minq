#!/bin/sh
docker build -f deploy/Dockerfile --no-cache -t mozilla/minq --build-arg SERVERNAME=minq.dev.mozaws.net .
docker tag mozilla/minq:latest mozilla/minq:$(git rev-parse HEAD)


