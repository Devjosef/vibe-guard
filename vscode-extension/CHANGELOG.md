# Change Log

All notable changes to the "Vibe-Guard" extension will be documented in this file.

## [0.0.1] - 2025-08-13

### Added
- Initial release of Vibe-Guard VS Code extension
- Basic security scanning integration
- Command palette integration ("Run Security Scan")
- Inline diagnostics display
- Output channel for detailed results
- Progress tracking during scans
- Configuration options for enabling/disabling

### Features
- Runs `vibe-guard scan . --format json` in workspace
- Parses JSON output and displays as VS Code diagnostics
- Maps severity levels (Critical/High → Error, Medium → Warning, Low → Info)
- Groups issues by file for better organization
- Shows detailed results in dedicated output channel

### Requirements
- Vibe-Guard must be installed globally: `npm install -g vibe-guard`
- VS Code 1.60.0 or higher
