# syntax=docker/dockerfile:1

FROM docker.io/golang:1.17

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download
COPY *.go ./

RUN apt update && apt install -y jq

RUN CGO_ENABLED=0 GOOS=linux go build -o /dtls_proxy

# Examples, can be overriden via docker run -e foo=bar
ENV CONNECT_ARG="0.0.0.0:5683"
ENV BIND_ARG="0.0.0.0:5684"
ENV PSK_SHELL_ARG="./lookup_psk"

CMD ["/bin/sh", "-c", "/dtls_proxy --connect $CONNECT_ARG --bind $BIND_ARG --shell-kms-cmd $PSK_SHELL_ARG"]
