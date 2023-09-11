export GO111MODULE=on

SHELL := /bin/bash

NAME = osctrld
CODE = *.go

DEST ?= /usr/local/bin

OUTPUT = bin

STATIC_ARGS = -ldflags "-linkmode external -extldflags -static"

.PHONY: build static clean

# Build code according to caller OS and architecture
build:
	go build -o $(OUTPUT)/$(NAME) $(CODE)

# Build everything statically
static:
	go build $(STATIC_ARGS) -o $(OUTPUT)/$(NAME) -a $(CODE)

# Delete all compiled binaries
clean:
	rm -rf $(OUTPUT)/$(NAME)

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

# Auto-format and simplify the code
GOFMT_ARGS = -l -w -s
gofmt:
	gofmt $(GOFMT_ARGS) ./$(TLS_CODE)

# Run all tests
test:
	go test . -v

# Check test coverage
test_cover:
	go test -cover .
