# Laravel Safeguard Documentation

Complete documentation for Laravel Safeguard package.

---

## Getting Started

- **[Installation Guide](installation.md)** — System requirements and installation steps
- **[Quick Start Guide](quick-start.md)** — Get up and running in 5 minutes

---

## Core Documentation

### Validation Rules

- **[All Validation Rules](validation-rules.md)** — Complete reference for all available rules
  - `safeguard` - All-in-one security
  - `safeguard_mime` - MIME type validation
  - `safeguard_php` - PHP code scanning
  - `safeguard_svg` - SVG XSS detection
  - `safeguard_image` - Image security
  - `safeguard_pdf` - PDF malware detection
  - `safeguard_dimensions` - Image dimensions
  - `safeguard_pages` - PDF page count

### Configuration

- **[Configuration Guide](configuration.md)** — Customize package behavior
  - MIME validation settings
  - Scanner configuration
  - Logging options
  - Environment variables

### Customization

- **[Customization Guide](customization.md)** — Extend and modify functionality
  - Add custom file types
  - Modify dangerous functions list
  - Exclude specific patterns
  - Custom validation logic

---

## Advanced Topics

- **[Logging & Monitoring](logging.md)** — Security event tracking
  - Enable logging
  - Custom log channels
  - Log format
  - Forensic analysis

- **[Advanced Usage](advanced.md)** — Complex scenarios
  - Form Request validation
  - Multiple file uploads
  - Conditional validation
  - Custom error messages
  - Performance optimization

- **[Examples](examples.md)** — Real-world use cases
  - User profile uploads
  - Document management
  - E-commerce product images
  - Multi-tenant file handling

---

## Reference

### API Documentation

All classes and methods with detailed parameters and return types.

#### Rules
- `Abdian\LaravelSafeguard\Rules\Safeguard`
- `Abdian\LaravelSafeguard\Rules\SafeguardMime`
- `Abdian\LaravelSafeguard\Rules\SafeguardPhp`
- `Abdian\LaravelSafeguard\Rules\SafeguardSvg`
- `Abdian\LaravelSafeguard\Rules\SafeguardImage`
- `Abdian\LaravelSafeguard\Rules\SafeguardPdf`
- `Abdian\LaravelSafeguard\Rules\SafeguardDimensions`
- `Abdian\LaravelSafeguard\Rules\SafeguardPages`

#### Scanners
- `Abdian\LaravelSafeguard\MimeTypeDetector`
- `Abdian\LaravelSafeguard\PhpCodeScanner`
- `Abdian\LaravelSafeguard\SvgScanner`
- `Abdian\LaravelSafeguard\ImageScanner`
- `Abdian\LaravelSafeguard\PdfScanner`

#### Utilities
- `Abdian\LaravelSafeguard\SecurityLogger`

---

## Additional Resources

- [GitHub Repository](https://github.com/abdian/laravel-safeguard)
- [Issue Tracker](https://github.com/abdian/laravel-safeguard/issues)
- [Changelog](../CHANGELOG.md)
- [Contributing Guide](../CONTRIBUTING.md)

---

## Need Help?

- Check the [FAQ section](advanced.md#faq) in Advanced Usage
- Search [existing issues](https://github.com/abdian/laravel-safeguard/issues)
- Open a [new discussion](https://github.com/abdian/laravel-safeguard/discussions)

---

## Version Information

This documentation is for **Laravel Safeguard v1.x**.

- **PHP:** 8.1+
- **Laravel:** 10.x, 11.x
- **Last Updated:** January 2025
