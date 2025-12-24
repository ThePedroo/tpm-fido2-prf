#!/bin/bash
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

# Stable extension ID (derived from the key in manifest.json)
DEFAULT_EXTENSION_ID="bfmfknknibchmioeamgbnlpakcjimnbf"

echo "=== TPM-FIDO Native Messaging Installation ==="
echo ""

# Build
echo "Building tpm-fido..."
cd "$PROJECT_DIR"
go build -o tpm-fido .

# Install binary
echo "Installing binary to ~/bin/tpm-fido..."
mkdir -p ~/bin
cp tpm-fido ~/bin/tpm-fido
chmod +x ~/bin/tpm-fido

# Detect browser config directory
CHROME_DIR="$HOME/.config/google-chrome/NativeMessagingHosts"
CHROMIUM_DIR="$HOME/.config/chromium/NativeMessagingHosts"

INSTALL_DIRS=()
if [ -d "$HOME/.config/google-chrome" ]; then
    INSTALL_DIRS+=("$CHROME_DIR")
fi
if [ -d "$HOME/.config/chromium" ]; then
    INSTALL_DIRS+=("$CHROMIUM_DIR")
fi

if [ ${#INSTALL_DIRS[@]} -eq 0 ]; then
    echo "Warning: No Chrome/Chromium config directory found"
    echo "Creating Chrome directory..."
    INSTALL_DIRS=("$CHROME_DIR")
fi

# Install native messaging manifest
MANIFEST_TEMPLATE="$PROJECT_DIR/com.vitorpy.tpmfido.json"

for INSTALL_DIR in "${INSTALL_DIRS[@]}"; do
    echo "Installing native messaging manifest to $INSTALL_DIR..."
    mkdir -p "$INSTALL_DIR"

    # Substitute home directory placeholder
    sed -e "s|__HOME__|$HOME|g" \
        "$MANIFEST_TEMPLATE" > "$INSTALL_DIR/com.vitorpy.tpmfido.json"
done

echo ""
echo "=== Installation complete ==="
echo ""
echo "Binary installed: ~/bin/tpm-fido"
echo "Extension ID: $DEFAULT_EXTENSION_ID"
echo ""
echo "Native messaging manifests installed:"
for INSTALL_DIR in "${INSTALL_DIRS[@]}"; do
    echo "  - $INSTALL_DIR/com.vitorpy.tpmfido.json"
done
echo ""
echo "Prerequisites:"
echo "  - User must have access to /dev/tpmrm0 (add to 'tss' group)"
echo "  - Fingerprint must be enrolled via fprintd"
echo ""
echo "Next steps:"
echo "  1. Load the extension in Chrome (chrome://extensions → Load unpacked)"
echo "  2. Restart Chrome"
echo "  3. Test on https://webauthn.io"
