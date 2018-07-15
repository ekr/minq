FROM golang

RUN go get github.com/bifurcation/mint
RUN (cd /go/src/github.com/bifurcation/mint; git remote add ekr https://github.com/ekr/mint; git fetch ekr; git checkout ekr/quic_record_layer)
RUN go get github.com/cloudflare/cfssl/helpers
RUN go get github.com/ekr/minq
RUN go install github.com/ekr/minq/bin/server
RUN go install github.com/ekr/minq/bin/client
RUN apt-get update
RUN apt-get install -y tcpdump
RUN curl -sL https://deb.nodesource.com/setup_6.x | bash -
RUN apt-get install -y nodejs
RUN (cd /go/src/github.com/ekr/minq/deploy/logserver; npm install)

ARG SERVERNAME=localhost
ENV SNAME=$SERVERNAME
ENV MINQ_LOG='connection,handshake,stream,packet'
ENTRYPOINT ["/bin/sh","/go/src/github.com/ekr/minq/deploy/run-looped.sh"]
CMD [$SNAME]

EXPOSE 4433/udp
EXPOSE 3000/tcp
       
