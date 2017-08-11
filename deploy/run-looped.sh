#!/bin/sh
while true; do
    echo -n "Starting server as "
    echo ${SNAME}
    /go/bin/server -addr 0.0.0.0:4433 -server-name ${SNAME}
    echo "Server crashed"
done
        
        
