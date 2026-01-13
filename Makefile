# TPM-FIDO Makefile
# Build and distribution targets for TPM-FIDO WebAuthn Platform Authenticator

BINARY_NAME := tpm-fido
VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
BUILD_TIME := $(shell date -u '+%Y-%m-%d_%H:%M:%S')
LDFLAGS := -s -w -X main.version=$(VERSION) -X main.buildTime=$(BUILD_TIME)

# Build directories
BUILD_DIR := build
DIST_DIR := dist

# Static build configuration
CC := musl-gcc
CGO_ENABLED := 1
STATIC_LDFLAGS := -linkmode external -extldflags '-static' $(LDFLAGS)

.PHONY: all clean build static test install uninstall dist help

# Default target
all: static

# Build static binary (recommended for distribution)
static:
	@echo "Building static binary..."
	CC=$(CC) CGO_ENABLED=$(CGO_ENABLED) go build \
		-ldflags="$(STATIC_LDFLAGS)" \
		-o $(BINARY_NAME) \
		tpmfido.go
	@echo "Static binary built: $(BINARY_NAME)"
	@file $(BINARY_NAME)

# Build dynamic binary (for development)
build:
	@echo "Building dynamic binary..."
	go build -ldflags="$(LDFLAGS)" -o $(BINARY_NAME) tpmfido.go
	@echo "Dynamic binary built: $(BINARY_NAME)"

# Build without CGO (pure Go, no C dependencies)
static-nocgo:
	@echo "Building pure Go static binary..."
	CGO_ENABLED=0 go build -ldflags="$(LDFLAGS)" -o $(BINARY_NAME) tpmfido.go
	@echo "Pure Go binary built: $(BINARY_NAME)"

# Run tests
test:
	go test -v ./...

# Install to local system
install: static
	@echo "Installing $(BINARY_NAME)..."
	install -D -m 755 $(BINARY_NAME) $(HOME)/bin/$(BINARY_NAME)
	@mkdir -p $(HOME)/.config/google-chrome/NativeMessagingHosts
	@mkdir -p $(HOME)/.config/chromium/NativeMessagingHosts
	@sed 's|__HOME__|$(HOME)|g' com.vitorpy.tpmfido.json > $(HOME)/.config/google-chrome/NativeMessagingHosts/com.vitorpy.tpmfido.json
	@sed 's|__HOME__|$(HOME)|g' com.vitorpy.tpmfido.json > $(HOME)/.config/chromium/NativeMessagingHosts/com.vitorpy.tpmfido.json
	@echo "Installed to $(HOME)/bin/$(BINARY_NAME)"
	@echo "Native messaging manifest installed for Chrome/Chromium"

# Uninstall from local system
uninstall:
	@echo "Uninstalling $(BINARY_NAME)..."
	rm -f $(HOME)/bin/$(BINARY_NAME)
	rm -f $(HOME)/.config/google-chrome/NativeMessagingHosts/com.vitorpy.tpmfido.json
	rm -f $(HOME)/.config/chromium/NativeMessagingHosts/com.vitorpy.tpmfido.json
	@echo "Uninstalled"

# Create distribution package
dist: static
	@echo "Creating distribution package..."
	@rm -rf $(DIST_DIR)
	@mkdir -p $(DIST_DIR)/$(BINARY_NAME)-$(VERSION)
	@mkdir -p $(DIST_DIR)/$(BINARY_NAME)-$(VERSION)/bin
	@mkdir -p $(DIST_DIR)/$(BINARY_NAME)-$(VERSION)/native-messaging-hosts
	@cp $(BINARY_NAME) $(DIST_DIR)/$(BINARY_NAME)-$(VERSION)/bin/
	@cp com.vitorpy.tpmfido.json $(DIST_DIR)/$(BINARY_NAME)-$(VERSION)/native-messaging-hosts/
	@cp Readme.md $(DIST_DIR)/$(BINARY_NAME)-$(VERSION)/ 2>/dev/null || true
	@cp LICENSE $(DIST_DIR)/$(BINARY_NAME)-$(VERSION)/ 2>/dev/null || true
	@echo '#!/bin/bash' > $(DIST_DIR)/$(BINARY_NAME)-$(VERSION)/install.sh
	@echo 'set -e' >> $(DIST_DIR)/$(BINARY_NAME)-$(VERSION)/install.sh
	@echo 'INSTALL_DIR="$$HOME/bin"' >> $(DIST_DIR)/$(BINARY_NAME)-$(VERSION)/install.sh
	@echo 'mkdir -p "$$INSTALL_DIR"' >> $(DIST_DIR)/$(BINARY_NAME)-$(VERSION)/install.sh
	@echo 'cp bin/$(BINARY_NAME) "$$INSTALL_DIR/"' >> $(DIST_DIR)/$(BINARY_NAME)-$(VERSION)/install.sh
	@echo 'chmod +x "$$INSTALL_DIR/$(BINARY_NAME)"' >> $(DIST_DIR)/$(BINARY_NAME)-$(VERSION)/install.sh
	@echo 'mkdir -p "$$HOME/.config/google-chrome/NativeMessagingHosts"' >> $(DIST_DIR)/$(BINARY_NAME)-$(VERSION)/install.sh
	@echo 'mkdir -p "$$HOME/.config/chromium/NativeMessagingHosts"' >> $(DIST_DIR)/$(BINARY_NAME)-$(VERSION)/install.sh
	@echo 'sed "s|__HOME__|$$HOME|g" native-messaging-hosts/com.vitorpy.tpmfido.json > "$$HOME/.config/google-chrome/NativeMessagingHosts/com.vitorpy.tpmfido.json"' >> $(DIST_DIR)/$(BINARY_NAME)-$(VERSION)/install.sh
	@echo 'sed "s|__HOME__|$$HOME|g" native-messaging-hosts/com.vitorpy.tpmfido.json > "$$HOME/.config/chromium/NativeMessagingHosts/com.vitorpy.tpmfido.json"' >> $(DIST_DIR)/$(BINARY_NAME)-$(VERSION)/install.sh
	@echo 'echo "Installation complete! Binary installed to $$INSTALL_DIR/$(BINARY_NAME)"' >> $(DIST_DIR)/$(BINARY_NAME)-$(VERSION)/install.sh
	@chmod +x $(DIST_DIR)/$(BINARY_NAME)-$(VERSION)/install.sh
	@cd $(DIST_DIR) && tar czf $(BINARY_NAME)-$(VERSION)-linux-x86_64-static.tar.gz $(BINARY_NAME)-$(VERSION)
	@echo "Distribution package created: $(DIST_DIR)/$(BINARY_NAME)-$(VERSION)-linux-x86_64-static.tar.gz"

# Clean build artifacts
clean:
	@echo "Cleaning build artifacts..."
	rm -f $(BINARY_NAME) tpmfido
	rm -rf $(BUILD_DIR) $(DIST_DIR)
	@echo "Clean complete"

# Show help
help:
	@echo "TPM-FIDO Build System"
	@echo ""
	@echo "Targets:"
	@echo "  make static       - Build static binary with musl (default, recommended)"
	@echo "  make build        - Build dynamic binary (development)"
	@echo "  make static-nocgo - Build pure Go static binary (no C deps)"
	@echo "  make test         - Run tests"
	@echo "  make install      - Install binary and Chrome manifest locally"
	@echo "  make uninstall    - Remove installed files"
	@echo "  make dist         - Create distribution tarball"
	@echo "  make clean        - Remove build artifacts"
	@echo "  make help         - Show this help"
