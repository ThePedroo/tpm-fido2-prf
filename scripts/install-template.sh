#!/bin/bash
# TPM-FIDO2 Platform Authenticator Installer
# Installs both the native binary and Chrome extension
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VERSION="${VERSION:-dev}"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Extension constants
EXTENSION_DIR_NAME="tpm-fido-extension"
EXTENSION_INSTALL_DIR="$HOME/.local/share/$EXTENSION_DIR_NAME"
EXTENSION_ID="bfmfknknibchmioeamgbnlpakcjimnbf"  # Stable ID from manifest key

echo "=== TPM-FIDO2 Platform Authenticator Installer ==="
echo "Version: $VERSION"
echo ""

# Track issues and warnings
ISSUES=()
WARNINGS=()

##############################################################################
# Phase 1: Prerequisites Check
##############################################################################

echo "Checking prerequisites..."
echo ""

# Check 1: Linux OS
if [[ ! "$OSTYPE" =~ linux.* ]]; then
    ISSUES+=("Not running on Linux (detected: $OSTYPE)")
fi

# Check 2: TPM device exists
if [ ! -e /dev/tpmrm0 ]; then
    ISSUES+=("TPM device /dev/tpmrm0 not found - TPM 2.0 hardware required")
else
    # Check access
    if [ ! -r /dev/tpmrm0 ] || [ ! -w /dev/tpmrm0 ]; then
        WARNINGS+=("Cannot access /dev/tpmrm0 - you may need to join 'tss' group")
    fi
fi

# Check 3: Chrome/Chromium installed
CHROME_FOUND=false
CHROME_PATHS=()
if command -v google-chrome &> /dev/null; then
    CHROME_FOUND=true
    CHROME_PATHS+=("google-chrome")
fi
if command -v chromium &> /dev/null; then
    CHROME_FOUND=true
    CHROME_PATHS+=("chromium")
fi
if command -v chromium-browser &> /dev/null; then
    CHROME_FOUND=true
    CHROME_PATHS+=("chromium-browser")
fi

if [ "$CHROME_FOUND" = false ]; then
    WARNINGS+=("Chrome/Chromium not found in PATH - extension will not work without a browser")
fi

# Check 4: fprintd (fingerprint daemon)
if ! command -v fprintd-list &> /dev/null; then
    WARNINGS+=("fprintd not found - fingerprint authentication will not work")
else
    # Check if fingerprints enrolled
    FINGERPRINTS=$(fprintd-list $USER 2>/dev/null | grep -c "finger" || echo "0")
    if [ "$FINGERPRINTS" -eq 0 ]; then
        WARNINGS+=("No fingerprints enrolled for $USER - run 'fprintd-enroll' to enroll")
    fi
fi

# Check 5: Detect if already installed
if [ -x "$HOME/bin/tpm-fido" ]; then
    EXISTING_VERSION=$($HOME/bin/tpm-fido -h 2>&1 | head -1 || echo "unknown")
    WARNINGS+=("tpm-fido already installed - will overwrite")
fi

if [ -d "$EXTENSION_INSTALL_DIR" ]; then
    WARNINGS+=("Extension already installed at $EXTENSION_INSTALL_DIR - will overwrite")
fi

# Display results
if [ ${#ISSUES[@]} -gt 0 ]; then
    echo -e "${RED}Installation cannot proceed. Issues found:${NC}"
    for issue in "${ISSUES[@]}"; do
        echo -e "  ${RED}✗${NC} $issue"
    done
    echo ""
    echo "Please resolve these issues and try again."
    exit 1
fi

if [ ${#WARNINGS[@]} -gt 0 ]; then
    echo -e "${YELLOW}Warnings (installation will continue):${NC}"
    for warning in "${WARNINGS[@]}"; do
        echo -e "  ${YELLOW}⚠${NC} $warning"
    done
    echo ""
fi

echo -e "${GREEN}✓${NC} All critical prerequisites met"
echo ""

##############################################################################
# Phase 2: Installation
##############################################################################

# Prompt for confirmation
echo "This will install:"
echo "  - Binary to: $HOME/bin/tpm-fido"
echo "  - Extension to: $EXTENSION_INSTALL_DIR"
echo "  - Native messaging manifest to: ~/.config/{google-chrome,chromium}/NativeMessagingHosts/"
echo ""
read -p "Continue? (y/N) " -n 1 -r
echo ""
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    echo "Installation cancelled"
    exit 0
fi

echo ""
echo "Installing TPM-FIDO2..."
echo ""

# Install binary
echo -n "Installing binary... "
mkdir -p "$HOME/bin"
if [ -f "$SCRIPT_DIR/bin/tpm-fido" ]; then
    cp "$SCRIPT_DIR/bin/tpm-fido" "$HOME/bin/tpm-fido"
    chmod +x "$HOME/bin/tpm-fido"
    echo -e "${GREEN}✓${NC}"
else
    echo -e "${RED}✗${NC}"
    echo "Error: Binary not found at $SCRIPT_DIR/bin/tpm-fido"
    exit 1
fi

# Install extension to permanent location
echo -n "Installing extension... "
mkdir -p "$EXTENSION_INSTALL_DIR"
if [ -d "$SCRIPT_DIR/extension" ]; then
    cp -r "$SCRIPT_DIR/extension/"* "$EXTENSION_INSTALL_DIR/"
    echo -e "${GREEN}✓${NC}"
else
    echo -e "${RED}✗${NC}"
    echo "Error: Extension directory not found at $SCRIPT_DIR/extension"
    exit 1
fi

# Install native messaging manifest
echo -n "Installing native messaging manifests... "

INSTALL_DIRS=()
if [ -d "$HOME/.config/google-chrome" ]; then
    INSTALL_DIRS+=("$HOME/.config/google-chrome/NativeMessagingHosts")
fi
if [ -d "$HOME/.config/chromium" ]; then
    INSTALL_DIRS+=("$HOME/.config/chromium/NativeMessagingHosts")
fi

if [ ${#INSTALL_DIRS[@]} -eq 0 ]; then
    # Create Chrome directory by default
    INSTALL_DIRS+=("$HOME/.config/google-chrome/NativeMessagingHosts")
fi

MANIFEST_INSTALLED=false
for INSTALL_DIR in "${INSTALL_DIRS[@]}"; do
    mkdir -p "$INSTALL_DIR"

    if [ -f "$SCRIPT_DIR/native-messaging-hosts/com.vitorpy.tpmfido.json" ]; then
        # Substitute placeholders
        sed -e "s|__HOME__|$HOME|g" \
            "$SCRIPT_DIR/native-messaging-hosts/com.vitorpy.tpmfido.json" \
            > "$INSTALL_DIR/com.vitorpy.tpmfido.json"
        MANIFEST_INSTALLED=true
    fi
done

if [ "$MANIFEST_INSTALLED" = true ]; then
    echo -e "${GREEN}✓${NC}"
else
    echo -e "${RED}✗${NC}"
    echo "Error: Native messaging manifest not found"
    exit 1
fi

##############################################################################
# Phase 3: Post-Installation
##############################################################################

echo ""
echo "=== Installation Complete ==="
echo ""
echo -e "${GREEN}✓${NC} Binary: $HOME/bin/tpm-fido"
echo -e "${GREEN}✓${NC} Extension: $EXTENSION_INSTALL_DIR"
echo -e "${GREEN}✓${NC} Extension ID: $EXTENSION_ID"
echo ""

# Test binary
if $HOME/bin/tpm-fido -h &> /dev/null; then
    echo -e "${GREEN}✓${NC} Binary test passed"
else
    echo -e "${YELLOW}⚠${NC} Binary test warning - check permissions"
fi

echo ""
echo "=== IMPORTANT: Load Extension in Chrome ==="
echo ""
echo "The extension has been installed but needs to be loaded in Chrome:"
echo ""
echo "  1. Open Chrome/Chromium"
echo "  2. Go to: chrome://extensions"
echo "  3. Enable 'Developer mode' (toggle in top-right)"
echo "  4. Click 'Load unpacked'"
echo "  5. Select directory: $EXTENSION_INSTALL_DIR"
echo "  6. Verify Extension ID matches: $EXTENSION_ID"
echo ""

# Offer to open chrome://extensions
if command -v xdg-open &> /dev/null; then
    read -p "Open chrome://extensions now? (Y/n) " -n 1 -r
    echo ""
    if [[ ! $REPLY =~ ^[Nn]$ ]]; then
        xdg-open "chrome://extensions" 2>/dev/null &
        echo -e "${GREEN}✓${NC} Opening chrome://extensions in your browser..."
        echo "    Please follow the steps above to load the extension."
    fi
fi

echo ""
echo "=== Next Steps ==="
echo ""

# Check TPM access
if [ ! -r /dev/tpmrm0 ] || [ ! -w /dev/tpmrm0 ]; then
    echo "1. ${YELLOW}Add yourself to 'tss' group for TPM access:${NC}"
    echo "   sudo usermod -aG tss $USER"
    echo "   ${YELLOW}Then LOG OUT and LOG BACK IN${NC}"
    echo ""
fi

# Check fingerprint enrollment
if command -v fprintd-list &> /dev/null; then
    FINGERPRINTS=$(fprintd-list $USER 2>/dev/null | grep -c "finger" || echo "0")
    if [ "$FINGERPRINTS" -eq 0 ]; then
        echo "2. ${YELLOW}Enroll fingerprint:${NC}"
        echo "   fprintd-enroll"
        echo ""
    fi
fi

echo "3. ${BLUE}Restart Chrome completely${NC} (close all windows)"
echo ""
echo "4. ${BLUE}Test at:${NC} https://webauthn.io"
echo ""

# Check if test-connection.sh exists
if [ -f "$SCRIPT_DIR/test-connection.sh" ]; then
    echo "Run '$SCRIPT_DIR/test-connection.sh' to verify native messaging setup"
    echo ""
fi

echo "Installation guide: https://github.com/vitorpy/tpm-fido2-prf"
echo ""
