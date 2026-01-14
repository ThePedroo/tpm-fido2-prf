#!/bin/bash
# TPM-FIDO2 Connection Test Script
# Verifies the native messaging setup is working correctly

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

EXTENSION_DIR="$HOME/.local/share/tpm-fido-extension"
EXTENSION_ID="bfmfknknibchmioeamgbnlpakcjimnbf"

echo "=== Testing TPM-FIDO Native Messaging Connection ==="
echo ""

ERRORS=0
WARNINGS=0

# Check binary exists and is executable
echo -n "Checking binary... "
if [ ! -x "$HOME/bin/tpm-fido" ]; then
    echo -e "${RED}✗${NC} Binary not found at $HOME/bin/tpm-fido"
    ERRORS=$((ERRORS + 1))
else
    echo -e "${GREEN}✓${NC} Found: $HOME/bin/tpm-fido"
fi

# Check extension exists
echo -n "Checking extension... "
if [ ! -d "$EXTENSION_DIR" ]; then
    echo -e "${RED}✗${NC} Extension not found at $EXTENSION_DIR"
    ERRORS=$((ERRORS + 1))
else
    echo -e "${GREEN}✓${NC} Found: $EXTENSION_DIR"

    # Verify key files exist
    for file in manifest.json background.js content.js inject.js; do
        if [ ! -f "$EXTENSION_DIR/$file" ]; then
            echo -e "  ${RED}✗${NC} Missing: $file"
            ERRORS=$((ERRORS + 1))
        fi
    done
fi

# Check native messaging manifest
echo -n "Checking native messaging manifests... "
MANIFEST_FOUND=false
for DIR in "$HOME/.config/google-chrome/NativeMessagingHosts" \
           "$HOME/.config/chromium/NativeMessagingHosts"; do
    MANIFEST_FILE="$DIR/com.vitorpy.tpmfido.json"
    if [ -f "$MANIFEST_FILE" ]; then
        echo -e "${GREEN}✓${NC} Found: $MANIFEST_FILE"
        MANIFEST_FOUND=true

        # Validate manifest content
        BINARY_PATH=$(grep -oP '"path":\s*"\K[^"]+' "$MANIFEST_FILE" 2>/dev/null || echo "")
        if [ -n "$BINARY_PATH" ] && [ "$BINARY_PATH" != "$HOME/bin/tpm-fido" ]; then
            echo -e "  ${YELLOW}⚠${NC} Warning: Binary path in manifest ($BINARY_PATH) doesn't match installed path"
            WARNINGS=$((WARNINGS + 1))
        fi

        # Check if extension ID is in allowed_origins
        if grep -q "$EXTENSION_ID" "$MANIFEST_FILE"; then
            echo -e "  ${GREEN}✓${NC} Extension ID ($EXTENSION_ID) is allowed"
        else
            echo -e "  ${RED}✗${NC} Extension ID not found in allowed_origins"
            ERRORS=$((ERRORS + 1))
        fi
    fi
done

if [ "$MANIFEST_FOUND" = false ]; then
    echo -e "${RED}✗${NC} No native messaging manifest found"
    ERRORS=$((ERRORS + 1))
fi

# Test binary execution
echo -n "Testing binary execution... "
if ! $HOME/bin/tpm-fido -h &> /dev/null; then
    echo -e "${RED}✗${NC} Binary failed to execute"
    ERRORS=$((ERRORS + 1))
else
    echo -e "${GREEN}✓${NC} Binary responds correctly"
fi

# Check TPM device
echo -n "Checking TPM device... "
if [ ! -e /dev/tpmrm0 ]; then
    echo -e "${RED}✗${NC} TPM device /dev/tpmrm0 not found"
    ERRORS=$((ERRORS + 1))
elif [ ! -r /dev/tpmrm0 ] || [ ! -w /dev/tpmrm0 ]; then
    echo -e "${YELLOW}⚠${NC} Cannot access /dev/tpmrm0"
    echo "  Run: sudo usermod -aG tss $USER"
    echo "  Then log out and back in"
    WARNINGS=$((WARNINGS + 1))
else
    echo -e "${GREEN}✓${NC} TPM device accessible: /dev/tpmrm0"
fi

# Check fingerprint enrollment
if command -v fprintd-list &> /dev/null; then
    echo -n "Checking fingerprint enrollment... "
    FINGERPRINTS=$(fprintd-list $USER 2>/dev/null | grep -c "finger" || echo "0")
    if [ "$FINGERPRINTS" -eq 0 ]; then
        echo -e "${YELLOW}⚠${NC} No fingerprints enrolled for $USER"
        echo "  Run: fprintd-enroll"
        WARNINGS=$((WARNINGS + 1))
    else
        echo -e "${GREEN}✓${NC} $FINGERPRINTS fingerprint(s) enrolled"
    fi
fi

# Summary
echo ""
echo "=== Test Summary ==="
if [ $ERRORS -gt 0 ]; then
    echo -e "${RED}✗ $ERRORS error(s) found${NC}"
    echo ""
    echo "Please fix the errors above before using TPM-FIDO."
    exit 1
elif [ $WARNINGS -gt 0 ]; then
    echo -e "${YELLOW}⚠ $WARNINGS warning(s) found${NC}"
    echo ""
    echo "The system will work but may have limitations."
    echo "Please review the warnings above."
else
    echo -e "${GREEN}✓ All checks passed${NC}"
    echo ""
    echo "The native messaging setup is correct."
fi

echo ""
echo "Next steps:"
echo "  1. Go to chrome://extensions"
echo "  2. Load extension from: $EXTENSION_DIR"
echo "  3. Verify Extension ID: $EXTENSION_ID"
echo "  4. Click 'Inspect views: service worker' to see console logs"
echo "  5. Test at https://webauthn.io"
echo ""
