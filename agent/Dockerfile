FROM golang:1.22-alpine AS builder
RUN apk add --no-cache libpcap-dev gcc musl-dev
WORKDIR /app
COPY go.work go.work
COPY pkg/ pkg/
COPY agent/ agent/
RUN cd agent && go build -o /agent .

FROM alpine:3.19
RUN apk add --no-cache ca-certificates libpcap
COPY --from=builder /agent /usr/local/bin/agent
ENTRYPOINT ["agent"]
