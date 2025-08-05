# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.1.3] - 2025-01-27

### Added
- **Complete Documentation Site**: Beautiful, responsive documentation with performance benchmarks
- **Performance Benchmarking**: Comprehensive speed testing with `npm run benchmark`
- **Multiple Output Formats**: SARIF and HTML report support
- **Configuration System**: Full `vibe-guard.json` configuration support
- **GitHub Pages Deployment**: Automated documentation deployment
- **Enhanced CLI**: Better error handling and user experience

### Changed
- **Performance Optimization**: Streamlined detection patterns across all security rules
- **Code Quality Improvements**: Eliminated redundant logic and overlapping patterns
- **Enhanced Maintainability**: Consolidated similar patterns for better code organization
- **Documentation**: Complete rewrite with performance metrics and benchmarks

### Fixed
- Eliminated redundant logic that was catching everything then filtering
- Removed duplicate pattern matching that slowed down scanning
- Improved code maintainability with cleaner rule implementations
- Fixed Vite build configuration for documentation deployment

## [1.1.2] - 2025-01-27

### Added
- **Scanner Sensitivity Documentation**: Added comprehensive section explaining VibeGuard's intelligent sensitivity design
- **False Positive Prevention Guide**: Detailed explanation of automatic filtering mechanisms
- **Detection Characteristics**: Clear expectations for detection rates and performance
- **Use Case Guidance**: Recommendations for development, production audits, and maximum sensitivity scenarios

### Changed
- Enhanced README with important sensitivity information
- Improved user understanding of scanner behavior
- Better transparency about detection capabilities

## [1.1.1] - 2025-01-27

### Changed
- Enhanced npm package description with specific vulnerability types
- Added OS and CPU architecture metadata
- Improved package.json formatting and metadata

## [1.1.0] - 2025-01-27

### Added
- **Complete Security Rule Coverage**: All 25 security rules now working and tested
- **Enhanced Vulnerability Detection**: Improved patterns and edge case handling
- **Comprehensive Testing**: All rules tested against real vulnerability examples
- **Zero False Positives**: Clean code no longer triggers false alarms
- **Improved Documentation**: Updated README with all 20 rules categorized by severity

### Security Rules (25 Total)
- **Critical (7)**: Exposed secrets, hardcoded sensitive data, XSS detection
- **High (12)**: Missing authentication, SQL injection, directory traversal, open CORS, CSRF protection, insecure deserialization, broken access control, insecure file upload, insecure session management
- **Medium (13)**: Unvalidated input, insecure HTTP, insecure dependencies, missing security headers, insecure random generation, insecure logging, insecure error handling, insecure configuration, AI-generated code validation, AI data leakage prevention, prompt injection detection, AI agent access control, MCP server security

### Changed
- Enhanced pattern detection for all security rules
- Improved false positive prevention mechanisms
- Updated package description and keywords
- Fixed circular dependency in package.json
- Enhanced distribution documentation

### Fixed
- All 25 security rules now properly detect vulnerabilities
- Eliminated false positives on clean code and test files
- Fixed edge cases in pattern matching
- Improved error handling and performance

## [1.0.1] - 2025-06-09

### Changed
- Updated package metadata and configuration
- Improved maintainer information
- Enhanced build process
- Added ARM64 support for macOS and Linux

## [1.0.0] - 2025-05-26

### Added
- Initial release of Vibe-Guard
- Security scanning capabilities
- Multiple vulnerability checks
- Cross-platform support (macOS, Linux, Windows)
- ARM64 support for macOS and Linux
- CLI interface with comprehensive options
- Integration with CI/CD pipelines

### Changed
- Improved build process
- Enhanced package distribution
- Updated maintainer information

### Fixed
- Initial release, no fixes yet 