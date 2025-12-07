---
layout: home

hero:
  name: Laravel Safeguard
  text: Secure File Upload Validation
  tagline: Protect your Laravel application from malicious file uploads with magic bytes detection, PHP code scanning, and comprehensive security checks.
  image:
    src: /hero-image.svg
    alt: Laravel Safeguard
  actions:
    - theme: brand
      text: Get Started
      link: /guide/getting-started
    - theme: alt
      text: View on GitHub
      link: https://github.com/abdian/laravel-safeguard

features:
  - icon: 🛡️
    title: All-in-One Security
    details: Single validation rule runs all security checks - MIME detection, PHP scanning, XSS detection, and more.

  - icon: 🔍
    title: Magic Bytes Detection
    details: Real MIME type validation using magic bytes - detects fake extensions and spoofed file types (70+ formats).

  - icon: ⚠️
    title: Malware Scanning
    details: Detects PHP code, XSS vulnerabilities, JavaScript in PDFs, and dangerous functions in uploaded files.

  - icon: 🖼️
    title: Image Security
    details: EXIF metadata scanning, GPS detection, malicious code in images, and automatic metadata stripping.

  - icon: 📄
    title: PDF Protection
    details: JavaScript detection, dangerous actions scanning, and page count validation for PDF files.

  - icon: 📏
    title: Size Validation
    details: Image dimensions and PDF page limits with fluent API configuration.

  - icon: 🚫
    title: Auto-Blocking
    details: Executables, scripts, and dangerous file types blocked automatically by default.

  - icon: 📊
    title: Security Logging
    details: Comprehensive threat monitoring and forensic logging for all security events.

  - icon: ⚙️
    title: Fully Customizable
    details: Fluent API, config-based control, custom signatures, and extensible patterns.
---

## Quick Start

Install via Composer:

```bash
composer require abdian/laravel-safeguard
```

Use in your validation:

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

## Why Laravel Safeguard?

Traditional file validation only checks extensions and client-provided MIME types - **both can be easily faked**. Laravel Safeguard validates files based on their actual binary content and scans for hidden threats.

### What it protects against:

- ✅ **File Type Spoofing** - Detects real file type via magic bytes
- ✅ **PHP Code Injection** - Scans for malicious PHP code in uploads
- ✅ **XSS Attacks** - Detects script tags and event handlers in SVG
- ✅ **Metadata Exploits** - Scans image EXIF for hidden code
- ✅ **PDF Malware** - Detects JavaScript and dangerous actions
- ✅ **Executable Files** - Auto-blocks .exe, scripts, and binaries

## Trusted By Developers

```php
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
```

## Laravel 10, 11, and 12 Compatible

Works seamlessly with Laravel 10.x, 11.x, and 12.x - no breaking changes, just security.
