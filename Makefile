VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -ldflags "-X main.version=$(VERSION)"

.PHONY: build test vet fmt lint scan clean

build:
	go build $(LDFLAGS) -o bin/qryx ./cmd/qryx

test:
	go test ./...

vet:
	go vet ./...

fmt:
	gofmt -w .

lint: vet
	@test -z "$$(gofmt -l .)" || (echo "gofmt needed:"; gofmt -l .; exit 1)

scan: build
	./bin/qryx scan ./testdata/sample

clean:
	rm -rf bin
