FROM golang:1.22-alpine

WORKDIR /app

COPY . .

RUN apk add --no-cache zip && \
    go build -o /app/cybedefend main.go

ENTRYPOINT ["/app/cybedefend"]
