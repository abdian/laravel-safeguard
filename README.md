# Laravel Safeguard

**Secure file upload validation for Laravel** — Protects your application from malicious file uploads using magic bytes detection, PHP code scanning, and comprehensive security checks.

[![Latest Version](https://img.shields.io/packagist/v/abdian/laravel-safeguard.svg)](https://packagist.org/packages/abdian/laravel-safeguard)
[![License](https://img.shields.io/packagist/l/abdian/laravel-safeguard.svg)](https://github.com/abdian/laravel-safeguard/blob/main/LICENSE)
[![PHP Version](https://img.shields.io/packagist/php-v/abdian/laravel-safeguard.svg)](https://packagist.org/packages/abdian/laravel-safeguard)

---

## Features

- **All-in-One Security** — Single validation rule runs all checks
- **Magic Bytes Detection** — Real MIME type validation (70+ formats)
- **Malware Scanning** — Detects PHP code, XSS, JavaScript in PDFs
- **Image Security** — EXIF metadata scanning, GPS detection
- **PDF Protection** — JavaScript and dangerous actions detection
- **Archive Scanning** — ZIP/TAR content analysis, zip bomb detection
- **Office Macro Detection** — VBA macro and ActiveX detection in DOCX/XLSX/PPTX
- **XXE Protection** — Prevents XML External Entity attacks in SVG files
- **Symlink Protection** — Prevents TOCTOU (time-of-check-time-of-use) attacks
- **Size Validation** — Image dimensions and PDF page limits
- **Auto-Blocking** — Executables and scripts blocked by default
- **Security Logging** — Comprehensive threat monitoring
- **Fully Customizable** — Fluent API and config-based control

---

## Installation

Install via Composer:

```bash
composer require abdian/laravel-safeguard
```

The package will auto-register via Laravel's package discovery.

### Publish Configuration (Optional)

```bash
php artisan vendor:publish --tag=safeguard-config
```

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
- Real MIME type detection
- PHP code scanning
- XSS vulnerability detection
- Image metadata analysis
- PDF security scanning

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

    // Office documents without macros
    'report' => ['required', (new Safeguard())
        ->documentsOnly()
        ->blockMacros()
    ],

    // Archives with content scanning
    'backup' => ['required', (new Safeguard())
        ->archivesOnly()
        ->scanArchives()
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
    'archive' => 'required|safeguard_archive',
    'report' => 'required|safeguard_office',
]);
```

---

## Validation Rules

### String Rules

| Rule | Description |
|------|-------------|
| `safeguard` | All-in-one comprehensive security check |
| `safeguard_mime:type1,type2` | Validate real MIME type via magic bytes |
| `safeguard_php` | Scan for malicious PHP code |
| `safeguard_svg` | Scan SVG for XSS and XXE attacks |
| `safeguard_image` | Analyze image EXIF metadata |
| `safeguard_pdf` | Scan PDF for JavaScript and threats |
| `safeguard_archive` | Scan archive contents for threats |
| `safeguard_office` | Detect macros in Office documents |
| `safeguard_dimensions:w,h` | Validate image dimensions |
| `safeguard_pages:min,max` | Validate PDF page count |

### Fluent API Methods

```php
use Abdian\LaravelSafeguard\Rules\Safeguard;

(new Safeguard())
    // Type filters
    ->imagesOnly()
    ->pdfsOnly()
    ->documentsOnly()
    ->archivesOnly()

    // MIME control
    ->allowedMimes(['image/jpeg', 'image/png'])
    ->strictExtensionMatching()

    // Image control
    ->maxDimensions(1920, 1080)
    ->minDimensions(100, 100)
    ->blockGps()
    ->stripMetadata()

    // PDF control
    ->maxPages(50)
    ->minPages(1)
    ->blockJavaScript()
    ->blockExternalLinks()

    // Archive control
    ->scanArchives()

    // Office control
    ->blockMacros()
```

---

## Security Features

### XXE Protection

Automatically prevents XML External Entity attacks in SVG files:

```xml
<!-- This attack is blocked -->
<?xml version="1.0"?>
<!DOCTYPE svg [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<svg>&xxe;</svg>
```

### Archive Scanning

Scans ZIP/TAR/RAR archives for:
- Dangerous file extensions (.php, .exe, .bat, etc.)
- Path traversal attacks (`../`)
- Zip bombs (high compression ratio)
- Excessive file counts
- Nested archives

```php
// Enable archive scanning
'backup' => ['required', (new Safeguard())->scanArchives()]

// Or use dedicated rule
'archive' => 'required|safeguard_archive'
```

### Office Macro Detection

Detects VBA macros and ActiveX controls in Office documents:

```php
// Block documents with macros
'document' => ['required', (new Safeguard())->blockMacros()]

// Or use dedicated rule
'report' => 'required|safeguard_office'

// Allow macros explicitly
'report' => 'required|safeguard_office:allow_macros'
```

### Symlink Protection

Prevents TOCTOU attacks by validating file paths:
- Rejects symbolic links
- Validates files are in allowed directories
- Prevents path traversal

---

## Configuration

### Archive Scanning

```php
// config/safeguard.php
'archive_scanning' => [
    'enabled' => false,                    // Enable by default
    'max_compression_ratio' => 100,        // Zip bomb detection (100:1)
    'max_uncompressed_size' => 500 * 1024 * 1024, // 500MB
    'max_files_count' => 10000,            // Max files in archive
    'max_nesting_depth' => 3,              // Nested archive depth
    'blocked_extensions' => [
        'php', 'phar', 'exe', 'bat', 'sh', 'cmd', 'ps1',
    ],
],
```

### Office Scanning

```php
'office_scanning' => [
    'enabled' => true,
    'block_macros' => true,                // Block VBA macros
    'block_activex' => true,               // Block ActiveX controls
    'allowed_macro_extensions' => ['docm', 'xlsm', 'pptm'],
],
```

### Security Settings

```php
'security' => [
    'check_symlinks' => true,              // TOCTOU protection
    'allowed_upload_paths' => null,        // null = auto-detect
],
```

### Environment Variables

```env
SAFEGUARD_ARCHIVE_SCAN=false
SAFEGUARD_OFFICE_SCAN=true
SAFEGUARD_BLOCK_MACROS=true
SAFEGUARD_BLOCK_ACTIVEX=true
SAFEGUARD_CHECK_SYMLINKS=true
```

---

## Requirements

- PHP 8.1 or higher
- Laravel 10.x, 11.x, or 12.x
- `fileinfo` PHP extension (enabled by default)
- `zip` PHP extension (for archive scanning)

---

## Security

Laravel Safeguard protects against:

| Threat | Protection |
|--------|------------|
| File Type Spoofing | Magic bytes detection |
| PHP Code Injection | Pattern-based scanning |
| XSS Attacks | SVG script/event detection |
| XXE Attacks | Entity declaration blocking |
| Metadata Exploits | EXIF code detection |
| PDF Malware | JavaScript/action detection |
| Zip Bombs | Compression ratio analysis |
| Office Macros | VBA/ActiveX detection |
| TOCTOU Attacks | Symlink validation |
| Path Traversal | Archive path validation |

For security vulnerabilities, please email security@example.com instead of using the issue tracker.

---

## License

Laravel Safeguard is open-sourced software licensed under the [MIT license](LICENSE).

---

## Links

- [Full Documentation](https://abdian.github.io/laravel-safeguard/)
- [GitHub Repository](https://github.com/abdian/laravel-safeguard)
- [Issue Tracker](https://github.com/abdian/laravel-safeguard/issues)
- [Changelog](CHANGELOG.md)
