#!/bin/bash
# TPM-FIDO2 Uninstall Script
# Removes the TPM-FIDO2 installation (preserves credentials)

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

EXTENSION_DIR="$HOME/.local/share/tpm-fido-extension"

echo "=== TPM-FIDO2 Uninstaller ==="
echo ""
echo "This will remove:"
echo "  - Binary: $HOME/bin/tpm-fido"
echo "  - Extension: $EXTENSION_DIR"
echo "  - Native messaging manifests"
echo ""
echo -e "${YELLOW}Credential data at ~/.local/share/tpm-fido/ will be preserved${NC}"
echo ""

read -p "Continue? (y/N) " -n 1 -r
echo ""
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    echo "Uninstall cancelled"
    exit 0
fi

echo ""
echo "Uninstalling..."
echo ""

# Remove binary
if [ -f "$HOME/bin/tpm-fido" ]; then
    rm "$HOME/bin/tpm-fido"
    echo -e "${GREEN}✓${NC} Removed binary"
else
    echo "  (Binary not found)"
fi

# Remove extension
if [ -d "$EXTENSION_DIR" ]; then
    rm -rf "$EXTENSION_DIR"
    echo -e "${GREEN}✓${NC} Removed extension"
else
    echo "  (Extension not found)"
fi

# Remove native messaging manifests
MANIFESTS_REMOVED=0
for DIR in "$HOME/.config/google-chrome/NativeMessagingHosts" \
           "$HOME/.config/chromium/NativeMessagingHosts"; do
    if [ -f "$DIR/com.vitorpy.tpmfido.json" ]; then
        rm "$DIR/com.vitorpy.tpmfido.json"
        echo -e "${GREEN}✓${NC} Removed manifest from $(basename $(dirname $DIR))"
        MANIFESTS_REMOVED=$((MANIFESTS_REMOVED + 1))
    fi
done

if [ $MANIFESTS_REMOVED -eq 0 ]; then
    echo "  (No native messaging manifests found)"
fi

echo ""
echo -e "${GREEN}Uninstall complete!${NC}"
echo ""
echo -e "${YELLOW}Note:${NC} Credential data preserved at ~/.local/share/tpm-fido/"
echo "To remove credentials: rm -rf ~/.local/share/tpm-fido/"
echo ""
