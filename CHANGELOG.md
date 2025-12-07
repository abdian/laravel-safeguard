# Changelog

All notable changes to Laravel Safeguard will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Support for Laravel 12.x
- Binary file detection to skip PHP scanning for safe file types (images, PDFs, videos, etc.)
- `isBinaryFile()` method to `MimeTypeDetector` class

### Fixed
- **Critical**: PHP scanning false positives on legitimate binary files (JPEG, PNG, PDF, etc.)
- **Critical**: Basic `safeguard` rule without MIME restrictions was rejecting all files
- Improved PHP tag detection patterns to reduce false positives
- More strict regex patterns for malicious code detection
- Removed overly aggressive patterns that caused false positives on normal text content
- `SafeguardMime` now allows all safe files when no MIME types are specified

### Changed
- PHP code scanning now skips binary files that cannot contain executable PHP code
- Updated suspicious pattern detection to be more precise and reduce false positives

## [1.0.0] - 2025-01-21

### Added
- Initial release
- Magic bytes MIME type detection (70+ file formats)
- PHP code scanning with 40+ dangerous functions
- SVG XSS vulnerability detection
- Image EXIF/GPS metadata scanning
- PDF JavaScript and malware detection
- Image dimensions validation
- PDF page count validation
- Comprehensive `safeguard` rule for all-in-one security
- Fluent API for rule configuration
- Security event logging system
- Customizable configuration for all features
- Support for Laravel 10.x and 11.x

[Unreleased]: https://github.com/abdian/laravel-safeguard/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/abdian/laravel-safeguard/releases/tag/v1.0.0
