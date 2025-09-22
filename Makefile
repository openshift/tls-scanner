# Makefile for check-network

# Binary name
BINARY_NAME=check-network

# Build directory
BUILD_DIR=bin

# Go parameters
GOCMD=go
GOBUILD=$(GOCMD) build
GOCLEAN=$(GOCMD) clean
GOTEST=$(GOCMD) test
GOGET=$(GOCMD) get
GOMOD=$(GOCMD) mod

# Default target
.PHONY: all
all: build

# Build the binary
.PHONY: build
build:
	mkdir -p $(BUILD_DIR)
	$(GOBUILD) -o $(BUILD_DIR)/$(BINARY_NAME) .

# Clean build artifacts
.PHONY: clean
clean:
	$(GOCLEAN)
	rm -rf $(BUILD_DIR)

# Download dependencies
.PHONY: deps
deps:
	$(GOMOD) download
	$(GOMOD) tidy

# Run tests
.PHONY: test
test:
	$(GOTEST) -v ./...

# Install the binary to GOPATH/bin
.PHONY: install
install:
	$(GOCMD) install .

# Install nmap dependency
.PHONY: install-nmap
install-nmap:
	@if command -v apt-get >/dev/null 2>&1; then \
		echo "Installing nmap using apt-get..."; \
		sudo apt-get update && sudo apt-get install -y nmap; \
	elif command -v yum >/dev/null 2>&1; then \
		echo "Installing nmap using yum..."; \
		sudo yum install -y nmap; \
	elif command -v dnf >/dev/null 2>&1; then \
		echo "Installing nmap using dnf..."; \
		sudo dnf install -y nmap; \
	elif command -v pacman >/dev/null 2>&1; then \
		echo "Installing nmap using pacman..."; \
		sudo pacman -S --noconfirm nmap; \
	else \
		echo "Package manager not detected. Please install nmap manually."; \
		exit 1; \
	fi

# Run the program with default parameters
.PHONY: run
run: build
	./$(BUILD_DIR)/$(BINARY_NAME)

# Help target
.PHONY: help
help:
	@echo "Available targets:"
	@echo "  build        - Build the binary"
	@echo "  clean        - Clean build artifacts"
	@echo "  deps         - Download and tidy dependencies"
	@echo "  test         - Run tests"
	@echo "  install      - Install binary to GOPATH/bin"
	@echo "  install-nmap - Install nmap dependency"
	@echo "  run          - Build and run with default parameters"
	@echo "  help         - Show this help message"