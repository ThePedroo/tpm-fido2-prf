#!/bin/bash
# TPM-FIDO2 Update Script
# Updates the TPM-FIDO2 installation to the latest version
set -e

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

echo "=== TPM-FIDO2 Update Script ==="
echo ""

# Check if installed
if [ ! -x "$HOME/bin/tpm-fido" ]; then
    echo -e "${RED}Error:${NC} tpm-fido not installed (expected at $HOME/bin/tpm-fido)"
    echo "Run install.sh first"
    exit 1
fi

# Get current version
echo -n "Current installation: "
if $HOME/bin/tpm-fido -h &> /dev/null; then
    echo -e "${GREEN}✓${NC} Found"
else
    echo -e "${RED}✗${NC} Binary not working"
fi
echo ""

# Option 1: Update from local tarball
if [ -n "$1" ]; then
    echo "Updating from local tarball: $1"
    TARBALL="$1"

    if [ ! -f "$TARBALL" ]; then
        echo -e "${RED}Error:${NC} Tarball not found: $TARBALL"
        exit 1
    fi

    # Extract to temp directory
    TEMP_DIR=$(mktemp -d)
    echo "Extracting to $TEMP_DIR..."
    tar -xzf "$TARBALL" -C "$TEMP_DIR"

    # Find install.sh in extracted directory
    INSTALL_SCRIPT=$(find "$TEMP_DIR" -name "install.sh" -type f | head -1)
    if [ -z "$INSTALL_SCRIPT" ]; then
        echo -e "${RED}Error:${NC} install.sh not found in tarball"
        rm -rf "$TEMP_DIR"
        exit 1
    fi

    # Run installer
    echo ""
    cd "$(dirname "$INSTALL_SCRIPT")"
    bash install.sh

    # Cleanup
    cd - > /dev/null
    rm -rf "$TEMP_DIR"

    echo ""
    echo -e "${GREEN}Update complete!${NC}"

# Option 2: Download latest from GitHub
else
    echo "Fetching latest release from GitHub..."

    # Get latest release URL
    LATEST_URL=$(curl -s https://api.github.com/repos/vitorpy/tpm-fido2-prf/releases/latest 2>/dev/null | \
                 grep "browser_download_url.*complete.*tar.gz" | \
                 cut -d '"' -f 4)

    if [ -z "$LATEST_URL" ]; then
        echo -e "${RED}Error:${NC} Could not find latest release"
        echo "You can manually download from: https://github.com/vitorpy/tpm-fido2-prf/releases"
        exit 1
    fi

    echo "Downloading: $LATEST_URL"

    # Download to temp directory
    TEMP_DIR=$(mktemp -d)
    cd "$TEMP_DIR"

    if ! curl -L -o tpm-fido-latest.tar.gz "$LATEST_URL"; then
        echo -e "${RED}Error:${NC} Download failed"
        cd - > /dev/null
        rm -rf "$TEMP_DIR"
        exit 1
    fi

    # Extract and install
    tar -xzf tpm-fido-latest.tar.gz
    cd tpm-fido-*/

    echo ""
    bash install.sh

    # Cleanup
    cd - > /dev/null
    rm -rf "$TEMP_DIR"

    echo ""
    echo -e "${GREEN}Update complete!${NC}"
fi

echo ""
echo -e "${YELLOW}Please restart Chrome to use the updated version${NC}"
echo ""
