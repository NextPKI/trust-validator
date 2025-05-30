FROM golang:1.24-alpine AS builder
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN go build -o trust-validator main.go

FROM alpine:latest
RUN apk add --no-cache ca-certificates openssl curl
COPY --from=builder /app/trust-validator /usr/local/bin/trust-validator
EXPOSE 8080
CMD ["trust-validator"]
