#!/bin/bash

# Vibe-Guard Release Script
# Usage: ./scripts/release.sh [patch|minor|major]

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if we're in the right directory
if [ ! -f "package.json" ]; then
    print_error "package.json not found. Please run this script from the project root."
    exit 1
fi

# Get current version
CURRENT_VERSION=$(node -p "require('./package.json').version")
print_status "Current version: $CURRENT_VERSION"

# Determine version bump type
BUMP_TYPE=${1:-patch}
if [[ ! "$BUMP_TYPE" =~ ^(patch|minor|major)$ ]]; then
    print_error "Invalid bump type. Use: patch, minor, or major"
    exit 1
fi

print_status "Bumping version: $BUMP_TYPE"

# Update version in package.json
NEW_VERSION=$(npm version $BUMP_TYPE --no-git-tag-version)
NEW_VERSION=${NEW_VERSION#v}  # Remove 'v' prefix

print_success "Version bumped to: $NEW_VERSION"

# Update VS Code extension version if it exists
if [ -f "vscode-extension/package.json" ]; then
    print_status "Updating VS Code extension version..."
    cd vscode-extension
    # Use node to directly update the version without npm scripts
    node -e "
    const fs = require('fs');
    const pkg = JSON.parse(fs.readFileSync('package.json', 'utf8'));
    pkg.version = '$NEW_VERSION';
    fs.writeFileSync('package.json', JSON.stringify(pkg, null, 2) + '\n');
    "
    cd ..
    print_success "VS Code extension version updated to $NEW_VERSION"
fi

# Update changelog
print_status "Updating CHANGELOG.md..."
TODAY=$(date +%Y-%m-%d)

# Check if CHANGELOG.md exists
if [ ! -f "CHANGELOG.md" ]; then
    print_warning "CHANGELOG.md not found, creating one..."
    cat > CHANGELOG.md << EOF
# Change Log

All notable changes to the Vibe-Guard project will be documented in this file.

## [$NEW_VERSION] - $TODAY

### Added
- Release automation script

### Changed
- Improved release process

### Fixed
- Version management

EOF
else
    # Add new version entry to existing changelog
    cat > temp_changelog.md << EOF
# Change Log

All notable changes to the Vibe-Guard project will be documented in this file.

## [$NEW_VERSION] - $TODAY

### Added
- Release automation script

### Changed
- Improved release process

### Fixed
- Version management

EOF

    # Append existing changelog content (skip the first version entry)
    tail -n +7 CHANGELOG.md >> temp_changelog.md
    mv temp_changelog.md CHANGELOG.md
fi

print_success "CHANGELOG.md updated"

# Build the project
print_status "Building project..."
npm run build

if [ $? -eq 0 ]; then
    print_success "Project built successfully"
else
    print_error "Build failed"
    exit 1
fi

# Build VS Code extension if it exists
if [ -f "vscode-extension/package.json" ]; then
    print_status "Building VS Code extension..."
    cd vscode-extension
    npm run compile
    
    if [ $? -eq 0 ]; then
        print_success "VS Code extension compiled successfully"
    else
        print_error "VS Code extension compilation failed"
        exit 1
    fi
    
    cd ..
fi

# Create git tag
print_status "Creating git tag: v$NEW_VERSION"
git add package.json CHANGELOG.md
if [ -f "vscode-extension/package.json" ]; then
    git add vscode-extension/package.json
fi
git commit -m "Release v$NEW_VERSION"
git tag "v$NEW_VERSION"

print_success "Git tag created: v$NEW_VERSION"

# Package VS Code extension if it exists
if [ -f "vscode-extension/package.json" ]; then
    print_status "Packaging VS Code extension..."
    cd vscode-extension
    npm run package
    
    if [ -f "vibe-guard-$NEW_VERSION.vsix" ]; then
        print_success "VS Code extension packaged: vibe-guard-$NEW_VERSION.vsix"
        # Move to root for easier access
        mv "vibe-guard-$NEW_VERSION.vsix" "../vibe-guard-$NEW_VERSION.vsix"
    else
        print_error "VS Code extension packaging failed"
        exit 1
    fi
    
    cd ..
fi

print_success "Release v$NEW_VERSION is ready!"
print_warning "Next steps:"
echo "  1. Test the project: npm test"
echo "  2. Push changes: git push origin main"
echo "  3. Push tag: git push origin v$NEW_VERSION"
if [ -f "vibe-guard-$NEW_VERSION.vsix" ]; then
    echo "  4. Create GitHub release with vibe-guard-$NEW_VERSION.vsix"
    echo "  5. Publish VS Code extension (when ready): cd vscode-extension && npm run publish"
fi
echo "  6. Publish npm package (when ready): npm publish"

print_status "Release script completed successfully! 🚀"
