FROM golang:1.24-alpine AS builder

WORKDIR /app

COPY go.mod ./
RUN go mod download

COPY . .

# Build for cluster
RUN CGO_ENABLED=0 GOOS=linux go build -o /app/check-network .

FROM registry.access.redhat.com/ubi8/ubi-minimal:latest

USER root

RUN microdnf install -y nmap tar lsof && microdnf clean all

COPY --from=builder /app/check-network /usr/local/bin/check-network

# Run as root for privileged operations
USER 0

ENV HOME=/root

CMD ["sleep", "infinity"]
