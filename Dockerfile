FROM golang

RUN go get github.com/bifurcation/mint
RUN go get github.com/ekr/minq
#ADD . /go/src/github.com/ekr/minq

RUN go install github.com/ekr/minq/bin/server

ARG SERVERNAME=localhost
ENV SNAME=$SERVERNAME
ENV MINQ_LOG='*'
ENTRYPOINT ["/bin/sh","/go/src/github.com/ekr/minq/docker/run-looped.sh"]
CMD [$SNAME]

EXPOSE 4433/udp
       
