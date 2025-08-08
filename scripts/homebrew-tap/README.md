# Homebrew Tap for Vibe-Guard

This is a Homebrew tap for installing [Vibe-Guard](https://github.com/Devjosef/vibe-guard), a security scanner for developers who code fast.

## Installation

```bash
# Add this tap
brew tap Devjosef/vibe-guard

# Install vibe-guard
brew install vibe-guard
```

## What is Vibe-Guard?

Vibe-Guard is a zero-dependency security scanner that helps developers identify potential security vulnerabilities in their codebases. It's designed to be fast, reliable, and easy to use.

### Features
- **Zero Setup**: Download and run, no Node.js or dependencies required
- **10 Essential Rules**: Catches the most common security issues
- **Made by Developers**: We know what actually breaks in production
- **Works Everywhere**: macOS, Linux, Windows, Docker, CI/CD
- **ARM64 Support**: Native support for Apple Silicon and ARM64 Linux

### Supported Platforms
- macOS (Intel & Apple Silicon)
- Linux (AMD64 & ARM64)
- Windows (x64)

## Usage

```bash
# Scan current directory
vibe-guard scan .

# Scan specific file
vibe-guard scan app.js

# Check version
vibe-guard --version
```

## More Information

- [GitHub Repository](https://github.com/Devjosef/vibe-guard)
- [Documentation](https://github.com/Devjosef/vibe-guard#readme)
- [Releases](https://github.com/Devjosef/vibe-guard/releases)

## License

MIT License - see the [LICENSE](https://github.com/Devjosef/vibe-guard/blob/main/LICENSE) file for details. 