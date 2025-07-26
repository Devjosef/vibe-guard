class VibeGuard < Formula
  desc "🛡️ Vibe-Guard Security Scanner - 20 essential security rules to catch vulnerabilities before they catch you!"
  homepage "https://github.com/Devjosef/vibe-guard"
  url "https://github.com/Devjosef/vibe-guard/archive/refs/tags/v1.1.1.tar.gz"
  sha256 "57c4d65834e7dc7088887ae51ec3da787e9c786523589ca9e22da2679f9c0ed7"
  license "MIT"
  head "https://github.com/Devjosef/vibe-guard.git", branch: "main"

  depends_on "node" => :build

  def install
    system "npm", "install"
    system "npm", "run", "build"
    
    # Install the binary
    bin.install "vibe-guard"
  end

  test do
    # Test that the binary works and can show help
    assert_match "Usage: vibe-guard", shell_output("#{bin}/vibe-guard --help", 0)
    
    # Test that version command works
    assert_match "1.1.1", shell_output("#{bin}/vibe-guard --version", 0)
    
    # Test that rules command works
    assert_match "Available Security Rules", shell_output("#{bin}/vibe-guard rules", 0)
  end
end 