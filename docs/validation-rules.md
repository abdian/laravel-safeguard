# Validation Rules Reference

Complete reference for all Laravel Safeguard validation rules.

---

## Overview

Laravel Safeguard provides 8 validation rules:

| Rule | Purpose | Example |
|------|---------|---------|
| `safeguard` | All-in-one security | `'file' => 'required\|safeguard'` |
| `safeguard_mime` | MIME type validation | `'file' => 'required\|safeguard_mime:image/jpeg'` |
| `safeguard_php` | PHP code scanning | `'file' => 'required\|safeguard_php'` |
| `safeguard_svg` | SVG XSS detection | `'icon' => 'required\|safeguard_svg'` |
| `safeguard_image` | Image security | `'photo' => 'required\|safeguard_image'` |
| `safeguard_pdf` | PDF malware detection | `'doc' => 'required\|safeguard_pdf'` |
| `safeguard_dimensions` | Image dimensions | `'avatar' => 'required\|safeguard_dimensions:1920,1080'` |
| `safeguard_pages` | PDF page count | `'doc' => 'required\|safeguard_pages:1,10'` |

---

## 1. Safeguard (All-in-One)

**Comprehensive security validation** — Runs all security checks automatically.

### String Rule

```php
$request->validate([
    'file' => 'required|safeguard',
]);
```

### Rule Object

```php
use Abdian\LaravelSafeguard\Rules\Safeguard;

$request->validate([
    'file' => ['required', new Safeguard()],
]);
```

### Fluent API

```php
$request->validate([
    'avatar' => ['required', (new Safeguard())
        ->imagesOnly()
        ->maxDimensions(1920, 1080)
        ->minDimensions(200, 200)
        ->blockGps()
        ->stripMetadata()
    ],

    'document' => ['required', (new Safeguard())
        ->pdfsOnly()
        ->maxPages(50)
        ->blockJavaScript()
        ->blockExternalLinks()
    ],
]);
```

### Available Methods

#### MIME Type Restrictions
```php
->allowedMimes(['image/jpeg', 'image/png'])
->imagesOnly()              // Only images
->pdfsOnly()                // Only PDFs
->documentsOnly()           // PDF, Word, Excel
```

#### Image Validation
```php
->maxDimensions(1920, 1080)
->minDimensions(200, 200)
->dimensions(200, 200, 1920, 1080)  // min & max
```

#### PDF Validation
```php
->maxPages(10)
->minPages(1)
->pages(1, 10)              // min & max
```

#### Security Options
```php
->blockGps()                // Block if GPS data found
->stripMetadata()           // Remove EXIF metadata
->blockJavaScript()         // Block if JavaScript in PDF
->blockExternalLinks()      // Block if external links in PDF
```

### What It Checks

- ✅ Real MIME type (magic bytes)
- ✅ PHP code in file content
- ✅ SVG XSS vulnerabilities (if SVG)
- ✅ Image EXIF metadata (if image)
- ✅ PDF malware (if PDF)
- ✅ Dangerous file types

---

## 2. SafeguardMime

**MIME type validation** using magic bytes detection.

### String Rule

```php
$request->validate([
    'avatar' => 'required|safeguard_mime:image/jpeg,image/png',
    'document' => 'required|safeguard_mime:application/pdf',
    'any_image' => 'required|safeguard_mime:image/*',
]);
```

### Rule Object

```php
use Abdian\LaravelSafeguard\Rules\SafeguardMime;

$request->validate([
    'avatar' => ['required', new SafeguardMime(['image/jpeg', 'image/png'])],
]);
```

### Wildcard Support

```php
'image' => 'required|safeguard_mime:image/*',      // Any image
'doc' => 'required|safeguard_mime:application/*',  // Any application
```

### Allow Dangerous Files

```php
use Abdian\LaravelSafeguard\Rules\SafeguardMime;

$request->validate([
    'script' => ['required', (new SafeguardMime(['application/javascript']))->allowDangerous()],
]);
```

### Supported Formats

**Images:** JPEG, PNG, GIF, BMP, TIFF, WebP, ICO
**Documents:** PDF, DOC, DOCX, XLS, XLSX, PPT, PPTX
**Archives:** ZIP, GZIP, RAR, 7-Zip, BZIP2, XZ
**Media:** MP4, MPEG, WebM, MP3, WAV, FLAC, OGG
**Blocked:** Executables, PHP, Scripts, JavaScript

[See full list in source code](../src/MimeTypeDetector.php)

---

## 3. SafeguardPhp

**PHP code scanning** — Detects malicious PHP code in uploaded files.

### String Rule

```php
$request->validate([
    'template' => 'required|safeguard_php',
]);
```

### Rule Object

```php
use Abdian\LaravelSafeguard\Rules\SafeguardPhp;

$request->validate([
    'template' => ['required', new SafeguardPhp()],
]);
```

### What It Detects

- PHP tags: `<?php`, `<?=`, `<?`
- Dangerous functions: `eval()`, `exec()`, `system()`, `shell_exec()`, `passthru()`
- File operations: `file_get_contents()`, `fopen()`, `file_put_contents()`
- Code execution: `base64_decode()`, `assert()`, `create_function()`
- Web shells: Common backdoor patterns

**Total:** 40+ dangerous functions

### Configuration

See [Configuration Guide](configuration.md#php-scanning) for customizing scanned functions.

---

## 4. SafeguardSvg

**SVG security scanning** — Detects XSS vulnerabilities in SVG files.

### String Rule

```php
$request->validate([
    'icon' => 'required|safeguard_svg',
    'logo' => 'required|safeguard_mime:image/svg+xml|safeguard_svg',
]);
```

### Rule Object

```php
use Abdian\LaravelSafeguard\Rules\SafeguardSvg;

$request->validate([
    'icon' => ['required', new SafeguardSvg()],
]);
```

### What It Detects

- **Script tags:** `<script>`
- **Event handlers:** `onclick`, `onload`, `onmouseover`, `onerror`
- **Dangerous protocols:** `javascript:`, `data:text/html`
- **Embedded objects:** `<iframe>`, `<embed>`, `<object>`
- **Obfuscated content:** Base64, URL encoding, HTML entities

---

## 5. SafeguardImage

**Image security scanning** — Analyzes image metadata and content.

### String Rule

```php
$request->validate([
    'avatar' => 'required|safeguard_image',
    'photo' => 'required|safeguard_mime:image/*|safeguard_image',
]);
```

### Rule Object

```php
use Abdian\LaravelSafeguard\Rules\SafeguardImage;

$request->validate([
    'avatar' => ['required', new SafeguardImage()],
]);
```

### Fluent API

```php
$request->validate([
    // Block if GPS found
    'profile_photo' => ['required', (new SafeguardImage())->blockGps()],

    // Auto-strip metadata
    'avatar' => ['required', (new SafeguardImage())->stripMetadata()],

    // Both
    'photo' => ['required', (new SafeguardImage())->blockGps()->stripMetadata()],
]);
```

### What It Scans

- **EXIF metadata:** Scans Comment, UserComment, ImageDescription, Artist, Copyright, Software
- **Trailing bytes:** Detects malicious code after image end marker
- **GPS location:** Identifies privacy-sensitive location data
- **Metadata stripping:** Optionally removes all EXIF data

### Example Detection

```php
// Image with PHP code in EXIF Comment field
// ❌ Blocked: "Suspicious PHP code found in EXIF Comment tag"
```

---

## 6. SafeguardPdf

**PDF security scanning** — Detects malicious content in PDF files.

### String Rule

```php
$request->validate([
    'document' => 'required|safeguard_pdf',
    'contract' => 'required|safeguard_mime:application/pdf|safeguard_pdf',
]);
```

### Rule Object

```php
use Abdian\LaravelSafeguard\Rules\SafeguardPdf;

$request->validate([
    'document' => ['required', new SafeguardPdf()],
]);
```

### Fluent API

```php
$request->validate([
    'contract' => ['required', (new SafeguardPdf())
        ->blockJavaScript()
        ->blockExternalLinks()
        ->withThreats()  // Show threat details in error message
    ],
]);
```

### What It Detects

- **JavaScript code:** `/JavaScript`, `/JS` actions with suspicious functions
- **Dangerous actions:** `/Launch`, `/SubmitForm`, `/ImportData`, `/GoToR`, `/EmbeddedFile`
- **External URLs:** Links to external resources
- **Form submissions:** Forms posting to external URLs
- **Obfuscated content:** Heavy compression, hex encoding, multiple encryption
- **Embedded files:** Detects executables and attachments

---

## 7. SafeguardDimensions

**Image dimensions validation** — Validates actual image width and height.

### String Rule

```php
$request->validate([
    // Max only
    'avatar' => 'required|safeguard_dimensions:1920,1080',

    // Max and min
    'banner' => 'required|safeguard_dimensions:1920,1080,800,600',
]);
```

**Parameters:** `max_width,max_height[,min_width,min_height]`

### Rule Object

```php
use Abdian\LaravelSafeguard\Rules\SafeguardDimensions;

$request->validate([
    'avatar' => ['required', new SafeguardDimensions(1920, 1080)],
    'banner' => ['required', new SafeguardDimensions(1920, 1080, 800, 600)],
]);
```

### Fluent API

```php
$request->validate([
    'avatar' => ['required', (new SafeguardDimensions())
        ->max(1920, 1080)
        ->min(200, 200)
        ->ratio(1.0)        // Square (1:1)
        ->square()          // Shortcut for ratio(1.0)
    ],
]);
```

### Available Methods

```php
->max(1920, 1080)           // Maximum dimensions
->min(200, 200)             // Minimum dimensions
->ratio(1.77, 0.01)         // Aspect ratio (16:9) with tolerance
->square()                  // Require square (1:1)
```

### Example Error Messages

```
"The avatar width must not exceed 1920 pixels. Current: 2400px."
"The banner height must be at least 600 pixels. Current: 400px."
"The avatar aspect ratio must be 1.00. Current: 1.33."
```

---

## 8. SafeguardPages

**PDF page count validation** — Validates number of pages in PDF.

### String Rule

```php
$request->validate([
    // Only max
    'document' => 'required|safeguard_pages:10',

    // Min and max
    'contract' => 'required|safeguard_pages:1,50',
]);
```

**Parameters:** `[min_pages,]max_pages`

### Rule Object

```php
use Abdian\LaravelSafeguard\Rules\SafeguardPages;

$request->validate([
    'document' => ['required', new SafeguardPages(1, 10)],
]);
```

### Fluent API

```php
$request->validate([
    'document' => ['required', (new SafeguardPages())
        ->min(1)
        ->max(50)
        ->exactly(10)       // Must be exactly 10 pages
    ],
]);
```

### Available Methods

```php
->min(1)                    // Minimum pages
->max(50)                   // Maximum pages
->exactly(10)               // Exact page count
```

### How It Works

Uses multiple detection methods for accuracy:
1. Counts `/Type /Page` entries
2. Checks `/Count` in `/Pages` object
3. Fallback page object counting

### Example Error Messages

```
"The document must have at least 1 page(s). Current: 0 page(s)."
"The contract must not exceed 50 page(s). Current: 75 page(s)."
```

---

## Combining Rules

Stack multiple rules for maximum security:

```php
$request->validate([
    'avatar' => [
        'required',
        'image',
        'max:5120',  // 5MB Laravel rule
        'safeguard_mime:image/jpeg,image/png',
        'safeguard_php',
        'safeguard_image',
        'safeguard_dimensions:1920,1080,200,200',
    ],

    'document' => [
        'required',
        'mimes:pdf',  // Laravel rule
        'max:10240',  // 10MB
        'safeguard_mime:application/pdf',
        'safeguard_php',
        'safeguard_pdf',
        'safeguard_pages:1,50',
    ],
]);
```

Or use the all-in-one `Safeguard` rule:

```php
use Abdian\LaravelSafeguard\Rules\Safeguard;

$request->validate([
    'avatar' => ['required', 'image', 'max:5120', (new Safeguard())
        ->allowedMimes(['image/jpeg', 'image/png'])
        ->maxDimensions(1920, 1080)
        ->minDimensions(200, 200)
        ->blockGps()
        ->stripMetadata()
    ],
]);
```

---

## Next Steps

- [Configuration Guide](configuration.md) — Customize rule behavior
- [Customization Guide](customization.md) — Extend functionality
- [Examples](examples.md) — Real-world use cases
