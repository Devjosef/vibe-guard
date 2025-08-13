# Vibe-Guard VS Code Extension

A VS Code extension that integrates Vibe-Guard security scanning directly into your editor.

## Features

- **Run Security Scan**: Execute Vibe-Guard scans from the command palette
- **Inline Diagnostics**: View security issues directly in your code with proper severity highlighting
- **Output Channel**: Detailed scan results in a dedicated output panel
- **Progress Tracking**: Visual feedback during scan execution

## Installation

1. Install Vibe-Guard globally: `npm install -g vibe-guard`
2. Install this extension in VS Code
3. Open a workspace folder
4. Use the command palette (`Cmd/Ctrl + Shift + P`) and run "Run Security Scan"

## Usage

### Manual Scan
1. Open the command palette (`Cmd/Ctrl + Shift + P`)
2. Type "Run Security Scan" and select it
3. Wait for the scan to complete
4. View results in the Problems panel and Output channel

### Configuration

The extension supports the following settings:

- `vibe-guard.enabled`: Enable/disable the extension (default: true)
- `vibe-guard.autoScan`: Automatically scan files on save (default: false)

## How It Works

1. The extension runs `vibe-guard scan . --format json` in your workspace
2. Parses the JSON output to extract security issues
3. Displays issues as VS Code diagnostics with appropriate severity levels
4. Shows detailed results in the Output channel

## Requirements

- Vibe-Guard must be installed globally: `npm install -g vibe-guard`
- VS Code 1.60.0 or higher

## Development

```bash
# Install dependencies
npm install

# Compile TypeScript
npm run compile

# Watch for changes
npm run watch
```

## License

MIT
