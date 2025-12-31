#!/bin/bash
# examples/example.sh - Examples of CLOBES PRO usage

echo "🚀 CLOBES PRO Examples"
echo "══════════════════════════════════════════════════"

# Check if CLOBES is installed
if ! command -v clobes >/dev/null 2>&1; then
    echo "CLOBES PRO is not installed. Run: sudo make install"
    exit 1
fi

echo ""
echo "1. Basic Information:"
echo "══════════════════════════════════════════════════"
clobes version
echo ""

echo "2. HTTP Operations (curl replacement):"
echo "══════════════════════════════════════════════════"
echo "Testing HTTP GET..."
clobes network get https://httpbin.org/get 2>/dev/null | head -3
echo ""

echo "3. System Information:"
echo "══════════════════════════════════════════════════"
clobes system info | head -5
echo ""

echo "4. File Operations:"
echo "══════════════════════════════════════════════════"
echo "Creating test file..."
echo "Hello CLOBES PRO" > /tmp/test_clobes.txt
clobes file hash /tmp/test_clobes.txt
echo ""

echo "5. Network Diagnostics:"
echo "══════════════════════════════════════════════════"
echo "Getting public IP..."
clobes network myip
echo ""

echo "6. Development Tools:"
echo "══════════════════════════════════════════════════"
echo "Compiling test program..."
cat > /tmp/test_program.c << 'EOF'
#include <stdio.h>
int main() {
    printf("Hello from CLOBES PRO!\n");
    return 0;
}
EOF
clobes dev compile /tmp/test_program.c
echo "Running compiled program..."
/tmp/test_program
echo ""

echo "7. Cryptography:"
echo "══════════════════════════════════════════════════"
echo "Generating password..."
clobes crypto generate-password 12
echo ""
echo "Base64 encoding..."
clobes crypto encode base64 "Hello CLOBES PRO"
echo ""

# Cleanup
rm -f /tmp/test_clobes.txt /tmp/test_program.c /tmp/test_program

echo "✅ Examples completed!"
echo ""
echo "For more commands: clobes help"
