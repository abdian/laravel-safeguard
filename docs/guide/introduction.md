# Introduction

## What is Laravel Safeguard?

Laravel Safeguard is a comprehensive security package for Laravel that protects your application from malicious file uploads. Unlike traditional validation that only checks file extensions and client-provided MIME types (which can be easily faked), Safeguard analyzes the actual binary content of files to detect their real type and scans for hidden threats.

## Why Do You Need It?

Traditional Laravel file validation:

```php
$request->validate([
    'file' => 'required|file|mimes:jpg,png,pdf|max:2048'
]);
```

**Problems:**
- ❌ Only checks file extension (easily faked)
- ❌ Trusts client-provided MIME type (can be spoofed)
- ❌ Doesn't detect PHP code hidden in images
- ❌ Doesn't scan for XSS in SVG files
- ❌ Doesn't check PDF for JavaScript malware
- ❌ Doesn't validate actual file content

## How Safeguard Solves This

With Laravel Safeguard:

```php
$request->validate([
    'file' => 'required|safeguard'
]);
```

**Protection:**
- ✅ Reads magic bytes to detect real file type
- ✅ Scans for 40+ dangerous PHP functions
- ✅ Detects XSS vulnerabilities in SVG
- ✅ Analyzes image EXIF metadata
- ✅ Scans PDFs for JavaScript and malware
- ✅ Blocks executables and scripts automatically

## Key Features

### 🔍 Magic Bytes Detection
Validates real MIME type by reading file signatures (magic bytes) - supports 70+ file formats.

```php
// Detects that a PHP file renamed to .jpg is NOT an image
$detector = new MimeTypeDetector();
$realType = $detector->detect($uploadedFile);
// Returns: 'application/x-php' instead of 'image/jpeg'
```

### ⚠️ PHP Code Scanning
Scans files for dangerous PHP functions like `eval()`, `exec()`, `system()`, base64 encoding, and web shell patterns.

```php
// Detects PHP code hidden in an image file
'file' => 'required|safeguard_php'
```

### 🖼️ Image Security
Analyzes EXIF metadata for malicious code, detects GPS location data, and can automatically strip metadata.

```php
'avatar' => ['required', (new Safeguard())
    ->imagesOnly()
    ->blockGps()
    ->stripMetadata()
]
```

### 📄 PDF Protection
Scans PDFs for JavaScript, dangerous actions (/Launch, /JavaScript), and validates page count.

```php
'document' => ['required', (new Safeguard())
    ->pdfsOnly()
    ->maxPages(50)
    ->blockJavaScript()
]
```

## Supported Laravel Versions

- Laravel 10.x ✅
- Laravel 11.x ✅
- Laravel 12.x ✅
- PHP 8.1+ required

## What's Next?

- [Installation](/guide/installation) - Get started in 5 minutes
- [Basic Usage](/guide/basic-usage) - Learn how to use Safeguard
- [Validation Rules](/guide/validation-rules) - See all available rules
