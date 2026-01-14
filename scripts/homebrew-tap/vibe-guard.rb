# Homebrew tap formula for Vibe-Guard
class VibeGuard < Formula
  # PKG information
  desc "██ Vibe-Guard Security Scanner - 25 essential security rules to catch vulnerabilities before they catch you!"
  homepage "https://github.com/Devjosef/vibe-guard"
  url "https://github.com/Devjosef/vibe-guard/archive/refs/tags/v1.2.1.tar.gz"
  sha256 "21880b7a6b0d4ef586c684bfb71240a85735844afea5b6668a2f11249b848581"
  license "MIT"
  head "https://github.com/Devjosef/vibe-guard.git", branch: "main"

  depends_on "node" => :build

  # This method is called during installation to place the binary in the correct location
  def install
    system "npm", "install"
    system "npm", "run", "build"

    # Install JS and create a small wrapper that runs node
    libexec.install Dir["dist/*"]
    (bin/"vibe-guard").write <<~EOS
      #!/bin/bash
      exec node #{libexec}/bin/vibe-guard.js "$@"
    EOS
    bin.install "vibe-guard"
  end

  # This method is called during installation to verify the installation
  test do
    # Test if the binary works and can show --help
    assert_match "Usage: vibe-guard", shell_output("#{bin}/vibe-guard --help", 0)
    
    # Test if the  --version command works
    assert_match "1.2.1", shell_output("#{bin}/vibe-guard --version", 0)
    
    # Test if the --rules command works
    assert_match "Available Security Rules", shell_output("#{bin}/vibe-guard rules", 0)
  end
end 