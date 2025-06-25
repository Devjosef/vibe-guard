# Setting Up the Homebrew Tap

This guide explains how to create and maintain the Homebrew tap for Vibe-Guard.

## What is a Homebrew Tap?

A Homebrew tap is a Git repository containing Homebrew formulae. It allows you to distribute your software via Homebrew without needing to meet the strict notability requirements of the main homebrew-core repository.

## Creating the Tap Repository

1. **Create a new GitHub repository** named `homebrew-vibe-guard`
   - Go to GitHub and create a new repository
   - Name it exactly: `homebrew-vibe-guard`
   - Make it public
   - Don't initialize with README (we'll add our own)

2. **Clone the repository locally**
   ```bash
   git clone https://github.com/Devjosef/homebrew-vibe-guard.git
   cd homebrew-vibe-guard
   ```

3. **Add the formula file**
   ```bash
   # Copy the formula from this directory
   cp ../vibe-guard.rb Formula/
   ```

4. **Add the README**
   ```bash
   # Copy the README from this directory
   cp ../README.md .
   ```

5. **Commit and push**
   ```bash
   git add .
   git commit -m "Initial commit: Add vibe-guard formula"
   git push origin main
   ```

## Usage

Once the tap is set up, users can install Vibe-Guard with:

```bash
# Add the tap
brew tap Devjosef/vibe-guard

# Install vibe-guard
brew install vibe-guard
```

## Updating the Formula

When you release a new version of Vibe-Guard:

1. **Update the version** in `Formula/vibe-guard.rb`
2. **Update the checksums** for all platforms
3. **Commit and push** the changes

## Benefits of a Personal Tap

- ✅ No notability requirements
- ✅ Full control over releases
- ✅ Can update immediately
- ✅ Users get the same `brew install` experience
- ✅ Can add multiple formulae if needed

## Alternative: Main Homebrew Repository

Once Vibe-Guard meets the notability requirements (>30 forks, >30 watchers, >75 stars), you can submit it to the main homebrew-core repository for even wider distribution. 