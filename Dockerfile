FROM golang:1.23-alpine AS builder

RUN apk update && apk add --no-cache git

WORKDIR /app

COPY go.mod go.sum ./

RUN go mod download

COPY . .

RUN go build -o authservice ./cmd/authservice

FROM alpine:latest

WORKDIR /root/

COPY --from=builder /app/authservice .

EXPOSE 8080

CMD ["./authservice"]
