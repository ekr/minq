#!/bin/sh
docker build --no-cache -t mozilla/minq --build-arg SERVERNAME=minq.dev.mozaws.net .
docker tag mozilla/minq:latest mozilla/minq:$(git rev-parse HEAD)


