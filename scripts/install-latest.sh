#!/bin/bash
# TPM-FIDO2 One-Liner Installer
# Usage: curl -sSL https://raw.githubusercontent.com/vitorpy/tpm-fido2-prf/main/scripts/install-latest.sh | bash
set -e

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

echo "=== TPM-FIDO2 One-Liner Installer ==="
echo ""

# Fetch latest release
echo "Fetching latest release from GitHub..."
LATEST_URL=$(curl -s https://api.github.com/repos/vitorpy/tpm-fido2-prf/releases/latest 2>/dev/null | \
             grep "browser_download_url.*complete.*tar.gz" | \
             cut -d '"' -f 4)

if [ -z "$LATEST_URL" ]; then
    echo -e "${RED}Error:${NC} Could not find latest release"
    echo ""
    echo "Please visit https://github.com/vitorpy/tpm-fido2-prf/releases"
    echo "and download the latest release manually."
    exit 1
fi

echo -e "${GREEN}✓${NC} Found latest release"
echo "Downloading: $LATEST_URL"
echo ""

# Download to temp directory
TEMP_DIR=$(mktemp -d)
cd "$TEMP_DIR"

if ! curl -L -o tpm-fido-latest.tar.gz "$LATEST_URL"; then
    echo -e "${RED}Error:${NC} Download failed"
    cd - > /dev/null
    rm -rf "$TEMP_DIR"
    exit 1
fi

echo -e "${GREEN}✓${NC} Download complete"
echo ""

# Extract
echo "Extracting..."
tar -xzf tpm-fido-latest.tar.gz
cd tpm-fido-*/

# Run installer
echo ""
bash install.sh

# Cleanup
cd /
rm -rf "$TEMP_DIR"
