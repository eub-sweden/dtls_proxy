# syntax=docker/dockerfile:1

FROM golang:1.17

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download
COPY *.go ./

RUN CGO_ENABLED=0 GOOS=linux go build -o /dtls_proxy

# These can be overriden via docker run -e foo=bar
ENV PSK_REST_ARG="https://localhost:12345"
ENV CONNECT_ARG="0.0.0.0:5683"
ENV BIND_ARG="0.0.0.0:5684"

CMD ["/bin/sh", "-c", "/dtls_proxy --connect $CONNECT_ARG --bind $BIND_ARG --psk-rest $PSK_REST_ARG"]
