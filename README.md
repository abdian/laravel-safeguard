# Laravel Safeguard

**Secure file upload validation for Laravel** — Protects your application from malicious file uploads using magic bytes detection, PHP code scanning, and comprehensive security checks.

[![Latest Version](https://img.shields.io/packagist/v/abdian/laravel-safeguard.svg)](https://packagist.org/packages/abdian/laravel-safeguard)
[![License](https://img.shields.io/packagist/l/abdian/laravel-safeguard.svg)](https://github.com/abdian/laravel-safeguard/blob/main/LICENSE)
[![PHP Version](https://img.shields.io/packagist/php-v/abdian/laravel-safeguard.svg)](https://packagist.org/packages/abdian/laravel-safeguard)

📖 **[Full Documentation](https://abdian.github.io/laravel-safeguard/)** | 🚀 **[Quick Start](#quick-start)** | 🔒 **[Security](#security)**

---

## Features

- 🛡️ **All-in-One Security** — Single validation rule runs all checks
- 🔍 **Magic Bytes Detection** — Real MIME type validation (70+ formats)
- ⚠️ **Malware Scanning** — Detects PHP code, XSS, JavaScript in PDFs
- 🖼️ **Image Security** — EXIF metadata scanning, GPS detection
- 📄 **PDF Protection** — JavaScript and dangerous actions detection
- 📏 **Size Validation** — Image dimensions and PDF page limits
- 🚫 **Auto-Blocking** — Executables and scripts blocked by default
- 📊 **Security Logging** — Comprehensive threat monitoring
- ⚙️ **Fully Customizable** — Fluent API and config-based control

---

## Installation

Install via Composer:

```bash
composer require abdian/laravel-safeguard
```

The package will auto-register via Laravel's package discovery.

---

## Quick Start

### Basic Usage (Recommended)

Use the `safeguard` rule for comprehensive security:

```php
use Illuminate\Http\Request;

public function upload(Request $request)
{
    $request->validate([
        'file' => 'required|safeguard',
    ]);

    // File is safe to process
}
```

This single rule performs:
- ✅ Real MIME type detection
- ✅ PHP code scanning
- ✅ XSS vulnerability detection
- ✅ Image metadata analysis
- ✅ PDF security scanning

### Advanced Configuration

```php
use Abdian\LaravelSafeguard\Rules\Safeguard;

$request->validate([
    // Images only with security
    'avatar' => ['required', (new Safeguard())
        ->imagesOnly()
        ->maxDimensions(1920, 1080)
        ->blockGps()
        ->stripMetadata()
    ],

    // PDFs with restrictions
    'document' => ['required', (new Safeguard())
        ->pdfsOnly()
        ->maxPages(50)
        ->blockJavaScript()
    ],
]);
```

### Individual Security Rules

For granular control, use specific validation rules:

```php
$request->validate([
    'avatar' => 'required|safeguard_mime:image/jpeg,image/png|safeguard_image',
    'icon' => 'required|safeguard_svg',
    'document' => 'required|safeguard_pdf|safeguard_pages:1,10',
]);
```

---

## Documentation

- **[Installation Guide](docs/installation.md)** — Complete installation instructions
- **[Quick Start Guide](docs/quick-start.md)** — Get started in 5 minutes
- **[Validation Rules](docs/validation-rules.md)** — All available rules and options
- **[Configuration](docs/configuration.md)** — Customize behavior and settings
- **[Customization](docs/customization.md)** — Add file types and patterns
- **[Logging & Monitoring](docs/logging.md)** — Security event logging
- **[Examples](docs/examples.md)** — Real-world usage examples
- **[Advanced Usage](docs/advanced.md)** — Complex scenarios and tips

---

## Requirements

- PHP 8.1 or higher
- Laravel 10.x, 11.x, or 12.x
- `fileinfo` PHP extension (enabled by default)

---

## Security

Laravel Safeguard helps protect against:

- **File Type Spoofing** — Detects real file type via magic bytes
- **PHP Code Injection** — Scans for malicious PHP code in uploads
- **XSS Attacks** — Detects script tags and event handlers in SVG
- **Metadata Exploits** — Scans image EXIF for hidden code
- **PDF Malware** — Detects JavaScript and dangerous actions
- **Executable Files** — Auto-blocks .exe, scripts, and binaries

For security vulnerabilities, please email security@example.com instead of using the issue tracker.

---

## License

Laravel Safeguard is open-sourced software licensed under the [MIT license](LICENSE).

---

## Links

- [Documentation](docs/)
- [GitHub Repository](https://github.com/abdian/laravel-safeguard)
- [Issue Tracker](https://github.com/abdian/laravel-safeguard/issues)
- [Changelog](CHANGELOG.md)
- [Contributing Guide](CONTRIBUTING.md)

---

<p align="center">
Made with ❤️ for the Laravel community
</p>
