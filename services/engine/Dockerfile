FROM golang:1.22-alpine AS builder
WORKDIR /app
COPY go.work go.work
COPY pkg/ pkg/
COPY services/engine/ services/engine/
RUN cd services/engine && go build -o /engine .

FROM alpine:3.19
RUN apk add --no-cache ca-certificates
COPY --from=builder /engine /usr/local/bin/engine
ENTRYPOINT ["engine"]
