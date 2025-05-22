export GO111MODULE=on

SHELL := /bin/bash

NAME = osctrld
CODE_DIR = cmd/${NAME}
CODE = *.go

DEST ?= /usr/local/bin

OUTPUT = bin
DIST = dist

STATIC_ARGS = -ldflags "-linkmode external -extldflags -static"

.PHONY: build static clean clean_go tidy install test test_cover release release-snapshot

# Build code according to caller OS and architecture
build:
	go build -o $(OUTPUT)/$(NAME) $(CODE_DIR)/$(CODE)

# Build everything statically
static:
	go build $(STATIC_ARGS) -o $(OUTPUT)/$(NAME) -a $(CODE_DIR)/$(CODE)

# Delete all compiled binaries
clean:
	rm -rf $(OUTPUT)/$(NAME)
	rm -rf $(DIST)/*

# Delete all dependencies go.sum files
clean_go:
	find . -name "go.sum" -type f -exec rm -rf {} \;

# Remove all unused dependencies
tidy:
	make clean
	make clean_go
	go mod tidy

# Install everything
# optional DEST=destination_path
install:
	make clean
	make build
	sudo cp $(OUTPUT)/$(NAME) $(DEST)

# Run all tests
test:
	go test . -v

# Check test coverage
test_cover:
	go test -cover .

# Release with goreleaser (for actual releases)
release:
	goreleaser release --clean

# Create a snapshot release for testing without publishing
release-snapshot:
	goreleaser release --snapshot --clean
