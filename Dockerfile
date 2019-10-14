# modified from
# https://github.com/shadowsocks/go-shadowsocks2/blob/master/Dockerfile
FROM golang:1.13.1-alpine3.10 AS builder

ENV GO111MODULE on
ENV GOPROXY https://goproxy.io

RUN apk update \
    && apk add git \
    && go get github.com/hmgle/socks5_go/cmd/socks5-server

FROM alpine:3.10 AS dist

ENV CRYPTO rc4
ENV KEY ''

LABEL Mingang.He="<dustgle@gmail.com>"

COPY --from=builder /go/bin/socks5-server /usr/bin/socks5-server

CMD exec socks5-server \
      -crypto $CRYPTO \
      -key $KEY \
