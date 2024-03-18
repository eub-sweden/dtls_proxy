# syntax=docker/dockerfile:1

FROM golang:1.22

# Set destination for COPY
WORKDIR /app

# Download Go modules
COPY go.mod go.sum ./
RUN go mod download

# Copy the source code. Note the slash at the end, as explained in
# https://docs.docker.com/engine/reference/builder/#copy
COPY *.go ./

# Build
RUN CGO_ENABLED=0 GOOS=linux go build -o /dtls_proxy

# Optional:
# To bind to a TCP port, runtime parameters must be supplied to the docker command.
# But we can document in the Dockerfile what ports
# the application is going to listen on by default.
# https://docs.docker.com/engine/reference/builder/#expose
EXPOSE 14881/udp

# Temporarily copy the template's keys.csv
COPY keys.csv ./

ENV UPSTR_ADDR=localhost
ENV UPSTR_PORT=14882
ENV KEYFILE=keys.csv

# Run
#CMD ["/dtls_proxy"]
CMD /dtls_proxy --bind 0.0.0.0:14881 --connect $UPSTR_ADDR:$UPSTR_PORT --psk-csv $KEYFILE