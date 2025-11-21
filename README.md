# Laravel Safeguard

**Secure file upload validation for Laravel** — detects real file types using magic bytes, preventing malicious uploads disguised with fake extensions.

## Features

- ✅ Real MIME type detection from file content (magic bytes)
- ✅ Blocks fake extensions (e.g., PHP files renamed to .jpg)
- ✅ Automatic dangerous file blocking (executables, scripts)
- ✅ Wildcard support (`image/*`)
- ✅ Fully customizable signatures and rules

## Installation

```bash
composer require abdian/laravel-safeguard
```

## Quick Start

### 1. MIME Type Validation

```php
use Illuminate\Http\Request;

public function upload(Request $request)
{
    $request->validate([
        'avatar' => 'required|safeguard_mime:image/jpeg,image/png',
        'document' => 'required|safeguard_mime:application/pdf',
        'any_image' => 'required|safeguard_mime:image/*',
    ]);
}
```

### 2. PHP Code Scanning

```php
$request->validate([
    'template' => 'required|safeguard_php',
    'upload' => 'required|safeguard_mime:image/*|safeguard_php',
]);
```

### 3. SVG Security Scanning

```php
$request->validate([
    'icon' => 'required|safeguard_svg',
    'logo' => 'required|safeguard_mime:image/svg+xml|safeguard_svg',
]);
```

### 4. Image Security Scanning

```php
$request->validate([
    'avatar' => 'required|safeguard_image',  // Scans EXIF, detects hidden code
    'photo' => 'required|safeguard_mime:image/*|safeguard_image',  // Full protection
]);
```

**Using Rule Objects:**

```php
use Abdian\LaravelSafeguard\Rules\{SafeguardMime, SafeguardPhp, SafeguardSvg, SafeguardImage};

$request->validate([
    'file' => ['required', new SafeguardMime(['image/jpeg']), new SafeguardPhp()],
    'icon' => ['required', new SafeguardSvg()],
    'avatar' => ['required', (new SafeguardImage())->blockGps()->stripMetadata()],
]);
```

## How It Works

### Magic Bytes Detection
Reads the first 16 bytes of files to detect their real type, preventing attacks where PHP files are disguised as images.

### PHP Code Scanning
Scans file content for dangerous patterns:
- PHP tags: `<?php`, `<?=`, `<?`
- Dangerous functions: `eval()`, `exec()`, `system()`, `base64_decode()`
- Web shell signatures: Common backdoor patterns
- Obfuscated code: Encoded payloads

### SVG Security Scanning
Detects XSS vulnerabilities in SVG files:
- `<script>` tags
- Event handlers: `onclick`, `onload`, `onmouseover`
- Dangerous protocols: `javascript:`, `data:text/html`
- Embedded objects: `<iframe>`, `<embed>`, `<object>`
- Obfuscated content: Base64, URL encoding, HTML entities

### Image Security Scanning
Analyzes images for hidden threats:
- **EXIF metadata**: Scans for PHP code in Comment, UserComment, etc.
- **Trailing bytes**: Detects malicious code after image end marker
- **GPS location**: Identifies privacy-sensitive location data
- **Metadata stripping**: Optionally removes all EXIF data

**Example:**
```php
$request->validate([
    'photo' => 'required|safeguard_image',
]);

// Image with PHP code in EXIF Comment field
// ❌ Blocked: Suspicious PHP code found in EXIF tag
```

## Supported File Types

**Images:** JPEG, PNG, GIF, BMP, TIFF, WebP, ICO
**Documents:** PDF, DOC, DOCX, XLS, XLSX, PPT, PPTX
**Archives:** ZIP, GZIP, RAR, 7-Zip, BZIP2, XZ
**Media:** MP4, MPEG, WebM, MP3, WAV, FLAC, OGG
**Blocked by default:** Executables, PHP, Scripts, JavaScript

[See complete list of magic bytes in source code](src/MimeTypeDetector.php)

## Configuration

Publish config (optional):

```bash
php artisan vendor:publish --tag=safeguard-config
```

**config/safeguard.php:**

```php
return [
    'mime_validation' => [
        'strict_check' => true,
        'block_dangerous' => true,
        'custom_signatures' => [],
        'dangerous_types' => [/* ... */],
    ],

    'php_scanning' => [
        'enabled' => true,
        'mode' => 'default',
        'exclude_functions' => [],
    ],

    'svg_scanning' => [
        'enabled' => true,
        'exclude_tags' => [],
        'exclude_attributes' => [],
    ],

    'image_scanning' => [
        'enabled' => true,
        'check_gps' => true,
        'block_gps' => false,
        'auto_strip_metadata' => false,
    ],
];
```

## Customization

### Add Custom File Types

Support additional formats by adding magic bytes signatures:

```php
// config/safeguard.php
'custom_signatures' => [
    '6674797068656963' => 'image/heic',  // iPhone photos
    '66747970617669' => 'image/avif',    // AVIF images
],
```

**Find magic bytes:**

```bash
# Linux/Mac
xxd -l 16 yourfile.ext

# Windows PowerShell
Format-Hex -Path yourfile.ext -Count 16

# PHP
$bytes = fread(fopen('file.ext', 'rb'), 16);
echo bin2hex($bytes);
```

### Customize PHP Scanning

**Scan Modes:**

```php
'php_scanning' => [
    'mode' => 'default',  // Options: 'default', 'strict', 'custom'
],
```

- **default**: Built-in dangerous functions + your additions
- **strict**: Only most dangerous (eval, exec, system, etc.)
- **custom**: Only scan for functions you specify

**Add Custom Functions:**

```php
'custom_dangerous_functions' => [
    'my_unsafe_function',
    'custom_risky_func',
],
```

**Exclude Specific Functions:**

```php
'exclude_functions' => [
    'file_get_contents',  // Allow this function
    'base64_decode',       // Allow this function
],
```

**Custom Mode (Only Scan Specific Functions):**

```php
'php_scanning' => [
    'mode' => 'custom',
    'scan_functions' => [
        'eval',
        'exec',
        'shell_exec',
        // Only these will be scanned
    ],
],
```

**Add/Exclude Patterns:**

```php
'custom_patterns' => [
    '/my_backdoor_pattern/i',
],

'exclude_patterns' => [
    '/base64_decode/i',  // Ignore this pattern
],
```

**Real-World Example:**

```php
// Scenario: Allow templates with base64_decode but block eval
'php_scanning' => [
    'mode' => 'default',
    'exclude_functions' => [
        'base64_decode',      // Allow for image encoding
        'file_get_contents',  // Allow for reading files
    ],
    'custom_dangerous_functions' => [
        'my_template_exec',   // Custom dangerous function
    ],
],
```

### Customize SVG Scanning

**Exclude Specific Tags/Attributes:**

```php
'svg_scanning' => [
    'exclude_tags' => [
        'animate',      // Allow SVG animations
        'animateTransform',
    ],

    'exclude_attributes' => [
        'onload',       // Allow onload in your app
    ],
],
```

**Add Custom Dangerous Items:**

```php
'custom_dangerous_tags' => [
    'video',        // Block video tags in SVG
    'audio',
],

'custom_dangerous_attributes' => [
    'ontouchstart',
    'ontouchend',
],
```

### Customize Image Scanning

**GPS and Metadata Options:**

```php
'image_scanning' => [
    'check_gps' => true,           // Check for GPS data
    'block_gps' => true,           // Block images with GPS
    'auto_strip_metadata' => true, // Remove all EXIF data
],
```

**Per-Field Control:**

```php
use Abdian\LaravelSafeguard\Rules\SafeguardImage;

$request->validate([
    // Block if GPS found
    'profile_photo' => ['required', (new SafeguardImage())->blockGps()],

    // Auto-strip metadata
    'avatar' => ['required', (new SafeguardImage())->stripMetadata()],

    // Both
    'photo' => ['required', (new SafeguardImage())->blockGps()->stripMetadata()],
]);
```

### Allow Dangerous Files Per Field

```php
use Abdian\LaravelSafeguard\Rules\SafeguardMime;

$request->validate([
    'avatar' => 'required|safeguard_mime:image/*',
    'script' => ['required', (new SafeguardMime(['application/javascript']))->allowDangerous()],
]);
```

## Environment Variables

```env
# MIME Type Validation
SAFEGUARD_MIME_STRICT=true
SAFEGUARD_MIME_BLOCK_DANGEROUS=true

# PHP Code Scanning
SAFEGUARD_PHP_SCAN=true

# SVG Security Scanning
SAFEGUARD_SVG_SCAN=true

# Image Security Scanning
SAFEGUARD_IMAGE_SCAN=true
SAFEGUARD_IMAGE_CHECK_GPS=true
SAFEGUARD_IMAGE_BLOCK_GPS=false
SAFEGUARD_IMAGE_STRIP_META=false
```

## Requirements

- PHP 8.1+
- Laravel 10.x or 11.x
- `fileinfo` extension (enabled by default)

## Security Best Practices

1. Always keep `strict_check` enabled in production
2. Store uploads outside webroot
3. Use random filenames
4. Combine with file size validation
5. Monitor security logs

## License

MIT License. See [LICENSE](LICENSE) file.

## Links

- [GitHub](https://github.com/abdian/laravel-safeguard)
- [Issues](https://github.com/abdian/laravel-safeguard/issues)
