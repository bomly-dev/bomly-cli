FROM alpine:3.22

RUN apk add --no-cache ca-certificates git \
  && addgroup -S bomly \
  && adduser -S -G bomly -h /home/bomly bomly

COPY bomly /usr/local/bin/bomly

USER bomly:bomly
WORKDIR /work
ENTRYPOINT ["/usr/local/bin/bomly"]
