BINARY ?= bin/caplock
OPA_BIN ?= opa
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo 0.1.0-dev)
LDFLAGS := -s -w -X github.com/1124875284/caplock/internal/version.Version=$(VERSION)

.PHONY: build install test test-race policy-test policy-report verify-rego fuzz cover lint fmt fmt-check vet check bench demo demo-screenshots demo-verify release-check clean-room release-dry-run security-negative ci-e2e clean

build:
	mkdir -p $(dir $(BINARY))
	go build -trimpath -ldflags '$(LDFLAGS)' -o $(BINARY) ./cmd/caplock

install:
	go install -trimpath -ldflags '$(LDFLAGS)' ./cmd/caplock

test:
	go test ./...

test-race:
	go test -race ./...

policy-test:
	go run ./cmd/caplock lint examples/policy/caplock.yaml --strict
	go run ./cmd/caplock test examples/policy/caplock.yaml

policy-report:
	go run ./cmd/caplock report examples/policy/caplock.yaml --format sarif -o caplock.sarif

verify-rego:
	CAPLOCK_OPA_BIN="$(OPA_BIN)" go test ./internal/exporter -run 'TestOPA(Evaluator|Selector)Parity' -count=1

fuzz:
	go test ./internal/config -run='^$$' -fuzz=FuzzParseJSONC -fuzztime=10s
	go test ./internal/lockfile -run='^$$' -fuzz=FuzzParse -fuzztime=10s
	go test ./internal/mcp -run='^$$' -fuzz=FuzzDecodeResponse -fuzztime=10s
	go test ./internal/manifest -run='^$$' -fuzz=FuzzHashSchema -fuzztime=10s
	go test ./internal/policy -run='^$$' -fuzz=FuzzCompile -fuzztime=10s

cover:
	go test -coverprofile=coverage.out ./...
	go tool cover -func=coverage.out

lint:
	golangci-lint run

fmt:
	gofmt -w $$(find cmd internal packs demo examples -name '*.go' -type f)

fmt-check:
	@test -z "$$(gofmt -l cmd internal packs demo examples)" || (echo 'gofmt required:'; gofmt -l cmd internal packs demo examples; exit 1)

vet:
	go vet ./...

check: fmt-check vet test policy-test lint

bench:
	./bench/run.sh

demo:
	./demo/run.sh

demo-screenshots:
	./demo/screenshots.sh

demo-verify:
	./demo/verify.sh

release-check:
	go test ./internal/releasechecks -v

clean-room:
	./scripts/clean-room.sh

release-dry-run:
	./scripts/release-dry-run.sh

security-negative:
	./scripts/security-negative.sh

ci-e2e:
	./demo/run.sh
	./bench/run.sh
	./demo/verify.sh

clean:
	rm -rf bin coverage.out
