#!/bin/bash

# Vibe-Guard Installation Script
# Usage: curl -L https://raw.githubusercontent.com/user/vibe-guard/main/install.sh | bash

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Detect platform
OS="$(uname -s)"
ARCH="$(uname -m)"

echo -e "${BLUE}🛡️  Vibe-Guard Security Scanner Installer${NC}"
echo -e "${BLUE}===========================================${NC}"

# Determine the binary name based on platform
case "$OS" in
    Darwin)
        BINARY_NAME="vibe-guard-macos"
        INSTALL_DIR="/usr/local/bin"
        ;;
    Linux)
        BINARY_NAME="vibe-guard-linux"
        INSTALL_DIR="/usr/local/bin"
        ;;
    MINGW*|MSYS*|CYGWIN*)
        BINARY_NAME="vibe-guard-win.exe"
        INSTALL_DIR="/usr/local/bin"
        ;;
    *)
        echo -e "${RED}❌ Unsupported operating system: $OS${NC}"
        exit 1
        ;;
esac

echo -e "${YELLOW}📋 Detected platform: $OS ($ARCH)${NC}"
echo -e "${YELLOW}📦 Binary: $BINARY_NAME${NC}"

# GitHub release URL (update this with your actual repository)
GITHUB_REPO="your-username/vibe-guard"
RELEASE_URL="https://github.com/$GITHUB_REPO/releases/latest/download/$BINARY_NAME"

# Download location
TEMP_FILE="/tmp/vibe-guard-download"
FINAL_LOCATION="$INSTALL_DIR/vibe-guard"

echo -e "${BLUE}⬇️  Downloading Vibe-Guard...${NC}"

# Download the binary
if command -v curl >/dev/null 2>&1; then
    curl -L "$RELEASE_URL" -o "$TEMP_FILE"
elif command -v wget >/dev/null 2>&1; then
    wget "$RELEASE_URL" -O "$TEMP_FILE"
else
    echo -e "${RED}❌ Neither curl nor wget found. Please install one of them.${NC}"
    exit 1
fi

# Check if download was successful
if [ ! -f "$TEMP_FILE" ]; then
    echo -e "${RED}❌ Download failed${NC}"
    exit 1
fi

echo -e "${BLUE}📦 Installing to $FINAL_LOCATION...${NC}"

# Install the binary
if [ -w "$INSTALL_DIR" ]; then
    mv "$TEMP_FILE" "$FINAL_LOCATION"
    chmod +x "$FINAL_LOCATION"
else
    echo -e "${YELLOW}🔐 Requesting sudo access to install to $INSTALL_DIR${NC}"
    sudo mv "$TEMP_FILE" "$FINAL_LOCATION"
    sudo chmod +x "$FINAL_LOCATION"
fi

# Verify installation
if [ -x "$FINAL_LOCATION" ]; then
    echo -e "${GREEN}✅ Vibe-Guard installed successfully!${NC}"
    echo ""
    echo -e "${BLUE}🚀 Quick start:${NC}"
    echo -e "  ${GREEN}vibe-guard scan .${NC}          # Scan current directory"
    echo -e "  ${GREEN}vibe-guard scan file.js${NC}    # Scan a specific file"
    echo -e "  ${GREEN}vibe-guard rules${NC}           # List available rules"
    echo -e "  ${GREEN}vibe-guard --help${NC}          # Show help"
    echo ""
    echo -e "${YELLOW}💡 Pro tip: Add vibe-guard to your CI/CD pipeline!${NC}"
    
    # Test the installation
    echo -e "${BLUE}🧪 Testing installation...${NC}"
    "$FINAL_LOCATION" version
else
    echo -e "${RED}❌ Installation failed${NC}"
    exit 1
fi 