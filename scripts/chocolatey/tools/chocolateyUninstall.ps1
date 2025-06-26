# Chocolatey uninstall script for Vibe-Guard
# This script handles the uninstallation process on Windows systems

# Stop on any error
$ErrorActionPreference = 'Stop'

# Package configuration
$packageName = 'vibe-guard'
$toolsDir = "$(Split-Path -parent $MyInvocation.MyCommand.Definition)"

# Remove the binary file
$binPath = Join-Path $toolsDir "vibe-guard.exe"
if (Test-Path $binPath) {
    Remove-Item $binPath -Force
}

# Remove the shim
Uninstall-BinFile -Name "vibe-guard" 