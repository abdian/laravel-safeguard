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

**Using Rule Object:**

```php
use Abdian\LaravelSafeguard\Rules\SafeguardMime;

$request->validate([
    'file' => ['required', new SafeguardMime(['image/jpeg', 'image/png'])],
]);
```

## How It Works

The package reads the first 16 bytes of uploaded files to detect their real type:

```php
// Attacker uploads malicious.php renamed to image.jpg
// Extension: .jpg (fake)
// Magic bytes: 3c3f706870 (<?php)

$request->validate([
    'avatar' => 'required|safeguard_mime:image/jpeg',
]);

// ❌ Validation fails: "File type not allowed for security reasons"
// ✅ Attack prevented!
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
        'strict_check' => true,        // Fail if extension doesn't match content
        'block_dangerous' => true,      // Block executables and scripts

        'custom_signatures' => [
            // Add your custom magic bytes here
        ],

        'dangerous_types' => [
            'application/x-php',
            'application/x-executable',
            // ... customize as needed
        ],
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

### Customize Dangerous Types

```php
// Remove JavaScript from blocked list
'dangerous_types' => [
    'application/x-php',
    'application/x-executable',
    // JavaScript removed
],

// Or disable completely
'block_dangerous' => false,
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
SAFEGUARD_MIME_STRICT=true
SAFEGUARD_MIME_BLOCK_DANGEROUS=true
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
