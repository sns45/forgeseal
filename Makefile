VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
COMMIT  ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo "none")
DATE    ?= $(shell date -u +"%Y-%m-%dT%H:%M:%SZ")

LDFLAGS = -s -w \
	-X github.com/sn45/forgeseal/internal/cli.version=$(VERSION) \
	-X github.com/sn45/forgeseal/internal/cli.commit=$(COMMIT) \
	-X github.com/sn45/forgeseal/internal/cli.date=$(DATE)

.PHONY: build test lint install clean

build:
	go build -ldflags '$(LDFLAGS)' -o bin/forgeseal ./cmd/forgeseal

test:
	go test -race -count=1 ./...

lint:
	golangci-lint run ./...

install:
	go install -ldflags '$(LDFLAGS)' ./cmd/forgeseal

clean:
	rm -rf bin/
