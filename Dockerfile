FROM golang

RUN go get github.com/bifurcation/mint
RUN go get github.com/ekr/minq
#ADD . /go/src/github.com/ekr/minq

RUN go install github.com/ekr/minq/bin/server

ENTRYPOINT sh /go/src/github.com/ekr/minq/docker/run-looped.sh

EXPOSE 4433/udp
       
