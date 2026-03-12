# Chocolatey installation script for Vibe-Guard

$ErrorActionPreference = 'Stop'

# Package configuration
$packageName = 'vibe-guard'
$toolsDir = "$(Split-Path -parent $MyInvocation.MyCommand.Definition)"
$filePath = Join-Path $toolsDir "vibe-guard-windows-x64.exe" 
$checksum = '{{ CHECKSUM }}'                                  
$checksumType = 'sha256'

# Install local executable
$packageArgs = @{
    packageName    = $packageName
    fileType       = 'exe'
    file           = $filePath                              
    checksum       = $checksum
    checksumType   = $checksumType
    validExitCodes = @(0)
}

Install-ChocolateyInstallPackage @packageArgs               

# Create system-wide shim
$binPath = Join-Path $toolsDir "vibe-guard.exe"
Install-BinFile "vibe-guard" $binPath                        
