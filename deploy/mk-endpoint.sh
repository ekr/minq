#!/bin/sh
docker build -f deploy/Dockerfile -t minq --build-arg SERVERNAME=minq.dev.mozaws.net .

