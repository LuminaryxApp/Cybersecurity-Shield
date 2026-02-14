.PHONY: test build dev clean

test:
	go test ./services/api/... -timeout 60s -race
	go test ./services/engine/... -timeout 60s -race
	go test ./agent/internal/collectors/logs/... -timeout 60s -race
	go test ./agent/internal/ml/... -timeout 60s -race
	go test ./agent/internal/collectors/cloud/... -timeout 60s

test-api:
	go test ./services/api/... -timeout 60s -race -v

test-engine:
	go test ./services/engine/... -timeout 60s -race -v

test-agent:
	go test ./agent/... -timeout 120s -v

build:
	go build ./services/api/...
	go build ./services/engine/...
	go build ./agent/...

build-api:
	go build -o bin/api ./services/api

build-engine:
	go build -o bin/engine ./services/engine

build-agent:
	go build -o bin/agent ./agent

build-dashboard:
	cd dashboard && npm run build

dev-api:
	go run ./services/api

dev-engine:
	go run ./services/engine

dev-agent:
	go run ./agent

dev-dashboard:
	cd dashboard && npm run dev

dev-infra:
	docker compose up -d timescaledb nats keycloak

clean:
	rm -rf bin/
	rm -rf dashboard/dist/

docker-up:
	docker compose up -d

docker-down:
	docker compose down

lint:
	cd dashboard && npm run lint
