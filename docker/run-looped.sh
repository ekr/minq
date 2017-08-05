#!/bin/sh
while true; do
    echo "Starting server"
    /go/bin/server -addr 0.0.0.0:4433
    echo "Server crashed"
done
        
        
