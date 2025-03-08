# Makefile for cybedefend CLI application

# Application name
APP_NAME := cybedefend

# Output directory
OUTPUT_DIR := dist

# Scripts directory
SCRIPTS_DIR := scripts

# Default target
.PHONY: all
all: build

# Build for the current platform
.PHONY: build
build:
	@$(SCRIPTS_DIR)/build.sh

# Cross-compile for all platforms
.PHONY: build-all
build-all:
	@$(SCRIPTS_DIR)/build-all.sh

# Clean build artifacts
.PHONY: clean
clean:
	@$(SCRIPTS_DIR)/clean.sh

# Run the application
.PHONY: run
run:
	@$(SCRIPTS_DIR)/run.sh

# Format the code
.PHONY: fmt
fmt:
	@$(SCRIPTS_DIR)/fmt.sh

# Lint the code (optional, requires golangci-lint)
.PHONY: lint
lint:
	@$(SCRIPTS_DIR)/lint.sh