# Homebrew formula for Vibe-Guard
# This formula handles installation of Vibe-Guard on macOS and Linux systems
class VibeGuard < Formula
  # Basic package information
  desc "🛡️ Security scanner for developers who code fast"
  homepage "https://github.com/Devjosef/vibe-guard"
  version "1.0.0"
  license "MIT"
  head "https://github.com/Devjosef/vibe-guard.git", branch: "main"

  # Platform-specific download URLs and checksums
  if OS.mac?
    # macOS ARM64 (Apple Silicon) specific configuration
    if Hardware::CPU.arm?
      url "https://github.com/Devjosef/vibe-guard/releases/download/v#{version}/vibe-guard-darwin-arm64.tar.gz"
      sha256 "YOUR_SHA256_HERE" # Replace with actual SHA256 after release
    # macOS Intel specific configuration
    else
      url "https://github.com/Devjosef/vibe-guard/releases/download/v#{version}/vibe-guard-darwin-amd64.tar.gz"
      sha256 "YOUR_SHA256_HERE" # Replace with actual SHA256 after release
    end
  elsif OS.linux?
    # Linux ARM64 specific configuration
    if Hardware::CPU.arm?
      url "https://github.com/Devjosef/vibe-guard/releases/download/v#{version}/vibe-guard-linux-arm64.tar.gz"
      sha256 "YOUR_SHA256_HERE" # Replace with actual SHA256 after release
    # Linux AMD64 specific configuration
    else
      url "https://github.com/Devjosef/vibe-guard/releases/download/v#{version}/vibe-guard-linux-amd64.tar.gz"
      sha256 "YOUR_SHA256_HERE" # Replace with actual SHA256 after release
    end
  end

  # Installation method
  # This method is called during installation to place the binary in the correct location
  def install
    bin.install "vibe-guard"  # Install the binary to Homebrew's bin directory
  end

  # Test method
  # This method is called during installation to verify the installation
  test do
    system "#{bin}/vibe-guard", "--version"  # Verify the binary works
  end

  # Add caveats about the open source nature
  def caveats
    <<~EOS
      Vibe-Guard is an open source project maintained by Josef and the Vibe-Guard community.
      For more information, visit: https://github.com/Devjosef/vibe-guard
    EOS
  end
end 