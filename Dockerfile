FROM golang:1.22-alpine
RUN groupadd -r appgroup && useradd -r -g appgroup appuser

WORKDIR /app

COPY . .

RUN apk add --no-cache zip=1.10-r0 && \
    go build -o /app/cybedefend main.go

ENTRYPOINT ["/app/cybedefend"]
ENTRYPOINT ["/app/cybedefend"]

