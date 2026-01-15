# Makefile for CLOBES PRO
CC = gcc
CFLAGS = -Wall -Wextra -O2 -D_GNU_SOURCE -I/usr/include -I/usr/local/include
LDFLAGS = -lcurl -lpthread -lm -lssl -lcrypto -lz
TARGET = clobes
SRC_DIR = src
OBJ_DIR = obj
BIN_DIR = /usr/local/bin

# Source files
SOURCES = $(SRC_DIR)/clobes.c
OBJECTS = $(OBJ_DIR)/clobes.o

# Default target
all: check_deps $(TARGET)

# Check dependencies
check_deps:
	@echo "Checking dependencies..."
	@if ! command -v curl-config >/dev/null 2>&1; then \
		echo "Error: libcurl is required. Install with: apk add curl-dev"; \
		exit 1; \
	fi
	@if ! pkg-config --exists libssl >/dev/null 2>&1; then \
		echo "Error: OpenSSL is required. Install with: apk add openssl-dev"; \
		exit 1; \
	fi
	@if ! pkg-config --exists zlib >/dev/null 2>&1; then \
		echo "Error: zlib is required. Install with: apk add zlib-dev"; \
		exit 1; \
	fi
	@echo "All dependencies found."

# Main target
$(TARGET): $(OBJECTS)
	@echo "Linking $(TARGET)..."
	@$(CC) $(OBJECTS) -o $(TARGET) $(LDFLAGS)
	@echo "Build complete: $(TARGET)"

# Compile source files
$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c
	@mkdir -p $(OBJ_DIR)
	@echo "Compiling $<..."
	@$(CC) $(CFLAGS) -c $< -o $@

# Install
install: $(TARGET)
	@echo "Installing $(TARGET) to $(BIN_DIR)..."
	@cp $(TARGET) $(BIN_DIR)/
	@chmod 755 $(BIN_DIR)/$(TARGET)
	@echo "Installation complete. Run: clobes --help"

# Uninstall
uninstall:
	@echo "Uninstalling $(TARGET)..."
	@rm -f $(BIN_DIR)/$(TARGET)
	@echo "Uninstall complete."

# Clean
clean:
	@echo "Cleaning..."
	@rm -rf $(OBJ_DIR) $(TARGET) www/*.html www/favicon.ico qr_code.png
	@echo "Clean complete."

# Generate SSL certificates
cert:
	@echo "Generating SSL certificates..."
	@openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes -subj "/C=FR/ST=Paris/L=Paris/O=CLOBES/CN=localhost" 2>/dev/null || (echo "Error: OpenSSL not installed. Install with: apk add openssl" && exit 1)
	@echo "Certificates generated: cert.pem, key.pem"

# Create test files
test:
	@echo "Creating test files..."
	@mkdir -p www
	@echo "<!DOCTYPE html>" > www/index.html
	@echo "<html>" >> www/index.html
	@echo "<head>" >> www/index.html
	@echo "    <title>CLOBES PRO Test</title>" >> www/index.html
	@echo "    <style>" >> www/index.html
	@echo "        body { font-family: Arial, sans-serif; margin: 40px; }" >> www/index.html
	@echo "        h1 { color: #2c3e50; }" >> www/index.html
	@echo "        .url { font-family: monospace; background: #f0f0f0; padding: 10px; }" >> www/index.html
	@echo "    </style>" >> www/index.html
	@echo "</head>" >> www/index.html
	@echo "<body>" >> www/index.html
	@echo "    <h1>🚀 CLOBES PRO Web Server</h1>" >> www/index.html
	@echo "    <p>This is a test page.</p>" >> www/index.html
	@echo "    <p class=\"url\">Access URL: http://localhost:8080</p>" >> www/index.html
	@echo "</body>" >> www/index.html
	@echo "</html>" >> www/index.html
	@echo "Test files created in www/ directory"

# Build and run
run: $(TARGET)
	@echo "Starting CLOBES PRO..."
	@./$(TARGET) --help

# Build and run server
server: $(TARGET)
	@echo "Starting HTTP server..."
	@./$(TARGET) server start --port 8080 --public

# Quick build (no dependencies check)
quick:
	@$(CC) $(CFLAGS) $(SOURCES) -o $(TARGET) $(LDFLAGS)
	@echo "Quick build complete: $(TARGET)"

# Debug build
debug: CFLAGS += -g -DDEBUG
debug: clean $(TARGET)
	@echo "Debug build complete"

# Static analysis
analyze:
	@echo "Running static analysis..."
	@cppcheck --enable=all --suppress=missingIncludeSystem $(SRC_DIR)/ 2>/dev/null || echo "Install cppcheck with: apk add cppcheck"

# Install dependencies (Alpine Linux)
deps-alpine:
	@echo "Installing dependencies for Alpine Linux..."
	@apk add --no-cache gcc make curl-dev openssl-dev zlib-dev musl-dev linux-headers

# Install dependencies (Ubuntu/Debian)
deps-ubuntu:
	@echo "Installing dependencies for Ubuntu/Debian..."
	@apt-get update && apt-get install -y gcc make libcurl4-openssl-dev libssl-dev zlib1g-dev

# Install dependencies (CentOS/RHEL)
deps-centos:
	@echo "Installing dependencies for CentOS/RHEL..."
	@yum install -y gcc make curl-devel openssl-devel zlib-devel

# Install qrencode for QR code support
qrencode:
	@echo "Installing qrencode for QR code support..."
	@apk add --no-cache qrencode 2>/dev/null || \
	apt-get install -y qrencode 2>/dev/null || \
	yum install -y qrencode 2>/dev/null || \
	echo "Could not install qrencode. QR codes will not be available."

# Create release package
dist: clean
	@echo "Creating release package..."
	@mkdir -p dist/clobes-pro
	@cp -r src Makefile README.md LICENSE www dist/clobes-pro/
	@tar -czf clobes-pro.tar.gz -C dist clobes-pro
	@rm -rf dist
	@echo "Release package created: clobes-pro.tar.gz"

# Install with all dependencies
install-full: deps-alpine qrencode $(TARGET) install
	@echo "Full installation complete."

# Help
help:
	@echo "CLOBES PRO Makefile Targets:"
	@echo ""
	@echo "  all          - Build CLOBES PRO (default)"
	@echo "  clean        - Remove build artifacts"
	@echo "  install      - Install to /usr/local/bin"
	@echo "  uninstall    - Remove from /usr/local/bin"
	@echo "  cert         - Generate SSL certificates"
	@echo "  test         - Create test files"
	@echo "  run          - Build and show help"
	@echo "  server       - Build and start HTTP server"
	@echo "  quick        - Quick build without checks"
	@echo "  debug        - Build with debug symbols"
	@echo "  analyze      - Run static analysis"
	@echo "  deps-alpine  - Install dependencies (Alpine)"
	@echo "  deps-ubuntu  - Install dependencies (Ubuntu)"
	@echo "  deps-centos  - Install dependencies (CentOS)"
	@echo "  qrencode     - Install qrencode for QR codes"
	@echo "  dist         - Create release package"
	@echo "  install-full - Install with all dependencies"
	@echo "  help         - Show this help"
	@echo ""
	@echo "Examples:"
	@echo "  make                    # Build CLOBES PRO"
	@echo "  make install            # Install system-wide"
	@echo "  make server             # Build and start server"
	@echo "  make install-full       # Full installation"
	@echo ""
	@echo "Server Examples:"
	@echo "  clobes server start --port 8080 --public"
	@echo "  clobes server start --ssl --gzip --qr"
	@echo "  clobes -i               # Interactive mode"

# List all targets
list:
	@grep '^[^#[:space:]].*:' Makefile | cut -d: -f1

# Phony targets
.PHONY: all check_deps install uninstall clean cert test run server quick debug analyze \
        deps-alpine deps-ubuntu deps-centos qrencode dist install-full help list
