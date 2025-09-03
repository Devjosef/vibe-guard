class VibeGuard < Formula
  desc "██ Vibe-Guard Security Scanner - 25 essential security rules to catch vulnerabilities before they catch you! Zero dependencies, instant setup, works everywhere, optimized performance."
  homepage "https://github.com/Devjosef/vibe-guard"
  url "https://github.com/Devjosef/vibe-guard/archive/refs/tags/v1.1.5.tar.gz"
  sha256 "435b67070ae7f6d478598fb5d45325354aa8a7ccd45224632895349f143b8abe"
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
    assert_match "1.1.5", shell_output("#{bin}/vibe-guard --version", 0)
    
    # Test that rules command works
    assert_match "Available Security Rules", shell_output("#{bin}/vibe-guard rules", 0)
  end
end 