FROM golang:1.22-alpine AS builder
WORKDIR /app
COPY go.work go.work
COPY pkg/ pkg/
COPY services/api/ services/api/
RUN cd services/api && go build -o /api .

FROM alpine:3.19
RUN apk add --no-cache ca-certificates
COPY --from=builder /api /usr/local/bin/api
ENTRYPOINT ["api"]
