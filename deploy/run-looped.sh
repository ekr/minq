#!/bin/sh
nodejs /go/src/github.com/ekr/minq/deploy/logserver/server.js /tmp/minq.log &
while true; do
    echo -n "Starting server as "
    echo ${SNAME}
    MINQ_LOG=connection,packet /go/bin/server -addr 0.0.0.0:4433 -server-name ${SNAME} -log /tmp/minq.log -http -standalone
    echo "Server crashed"
done
        
        
