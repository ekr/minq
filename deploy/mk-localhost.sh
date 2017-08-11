#!/bin/sh
docker build -f deploy/Dockerfile -t minq --build-arg SERVERNAME=localhost .

