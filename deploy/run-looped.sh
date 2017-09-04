#!/bin/sh
node deploy/logserver/server.js /tmp/minq.log &
while true; do
    echo -n "Starting server as "
    echo ${SNAME}
    /go/bin/server -addr 0.0.0.0:4433 -server-name ${SNAME} -log /tmp/minq.log
    echo "Server crashed"
done
        
        
