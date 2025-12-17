#!/bin/bash
set -euo pipefail

OS="$(uname -s)"
ARCH="$(uname -m)"

case "$OS" in
  Darwin)
    if [[ "$ARCH" = arm64 ]]; then
      BINARY="vibe-guard-macos-arm64"
      EXPECTED_SHA256="cc5dc2f9768e681b7b5eefe4244d686e55006e76650d63a3d66dcd6c104f9c71"
    else
      BINARY="vibe-guard-macos-x64"
      EXPECTED_SHA256="4a498734c448e002bf9c759d711530a350179b0683261d3047153e973fe2067b"
    fi
    ;;
  Linux)
    if [[ "$ARCH" =~ ^(aarch64|arm64)$ ]]; then
      BINARY="vibe-guard-linux-arm64"
      EXPECTED_SHA256="7ddaa5461a46bbbcbac7c144d1d7beaef7408ecadb1a9884c9fc7d9d928834f5"
    else
      BINARY="vibe-guard-linux-x64"
      EXPECTED_SHA256="80d25b4c31cf43e10962836e50265b1b9c601eb0413f1083328778200400fa05"
    fi
    ;;
  MINGW*|MSYS*|CYGWIN*)
    BINARY="vibe-guard-windows-x64.exe"
    EXPECTED_SHA256="6ba2c5f4e09825391164f8a1626e0886e8893daf5a9b86dcc85d311191a4daa1"
    ;;
  *)
    echo "Unsupported: $OS $ARCH" >&2
    exit 1
    ;;
esac

URL="https://github.com/Devjosef/vibe-guard/releases/latest/download/$BINARY"
DEST="/usr/local/bin/vibe-guard"
TEMP="/tmp/vibe-guard.$$"

echo "Installing $BINARY to $DEST"

curl -Lfs "$URL" -o "$TEMP"
echo "$EXPECTED_SHA256  $TEMP" | sha256sum -c - || { echo "Checksum failed" >&2; rm "$TEMP"; exit 1; }
 
if [[ ! -w "$(dirname "$DEST")" ]]; then
  sudo mv "$TEMP" "$DEST" && sudo chmod +x "$DEST"
else
  mv "$TEMP" "$DEST" && chmod +x "$DEST"
fi

"$DEST" version && echo "Done."
