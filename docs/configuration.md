# Configuration Guide

Complete guide to configuring Laravel Safeguard.

---

## Publishing Configuration

Publish the configuration file:

```bash
php artisan vendor:publish --tag=safeguard-config
```

This creates `config/safeguard.php`.

---

## Configuration File Structure

```php
return [
    'mime_validation' => [...],
    'php_scanning' => [...],
    'svg_scanning' => [...],
    'image_scanning' => [...],
    'pdf_scanning' => [...],
    'logging' => [...],
];
```

---

## MIME Type Validation

### Basic Configuration

```php
'mime_validation' => [
    // Fail if detected MIME doesn't match client-provided type
    'strict_check' => env('SAFEGUARD_MIME_STRICT', true),

    // Automatically block dangerous file types
    'block_dangerous' => env('SAFEGUARD_MIME_BLOCK_DANGEROUS', true),

    // Custom magic bytes signatures
    'custom_signatures' => [],

    // Dangerous MIME types to block
    'dangerous_types' => [
        'application/x-msdownload',  // .exe
        'application/x-php',         // .php
        'text/x-shellscript',        // .sh
        // ... (25+ types)
    ],
],
```

### Environment Variables

```env
SAFEGUARD_MIME_STRICT=true
SAFEGUARD_MIME_BLOCK_DANGEROUS=true
```

### Add Custom File Types

```php
'custom_signatures' => [
    '6674797068656963' => 'image/heic',  // iPhone HEIC
    '66747970617669' => 'image/avif',    // AVIF images
],
```

**How to find magic bytes:**

```bash
# Linux/Mac
xxd -l 16 file.ext

# Windows PowerShell
Format-Hex -Path file.ext -Count 16

# PHP
$bytes = fread(fopen('file.ext', 'rb'), 16);
echo bin2hex($bytes);
```

---

## PHP Code Scanning

### Basic Configuration

```php
'php_scanning' => [
    // Enable PHP code scanning
    'enabled' => env('SAFEGUARD_PHP_SCAN', true),

    // Scan mode: 'default', 'strict', 'custom'
    'mode' => 'default',

    // Functions to scan for (used when mode = 'custom')
    'scan_functions' => [],

    // Additional dangerous functions to detect
    'custom_dangerous_functions' => [],

    // Functions to exclude from scanning
    'exclude_functions' => [],

    // Additional suspicious patterns (regex)
    'custom_patterns' => [],

    // Patterns to exclude from scanning
    'exclude_patterns' => [],
],
```

### Environment Variables

```env
SAFEGUARD_PHP_SCAN=true
```

### Scan Modes

#### Default Mode
Uses built-in list + your custom additions - excludes your exclusions.

```php
'mode' => 'default',
'custom_dangerous_functions' => [
    'my_unsafe_function',
],
'exclude_functions' => [
    'file_get_contents',  // Allow this function
],
```

#### Strict Mode
Only scans the most dangerous functions:

```php
'mode' => 'strict',
```

Scans only: `eval`, `assert`, `exec`, `shell_exec`, `system`

#### Custom Mode
Only scan functions you specify:

```php
'mode' => 'custom',
'scan_functions' => [
    'eval',
    'exec',
    'shell_exec',
],
```

### Real-World Example

```php
// Allow templates with base64_decode but block eval
'php_scanning' => [
    'mode' => 'default',
    'exclude_functions' => [
        'base64_decode',      // Allow for image encoding
        'file_get_contents',  // Allow for reading files
    ],
    'custom_dangerous_functions' => [
        'my_template_exec',   // Custom dangerous function
    ],
    'custom_patterns' => [
        '/backdoor/i',        // Custom pattern
    ],
],
```

---

## SVG Security Scanning

### Basic Configuration

```php
'svg_scanning' => [
    // Enable SVG security scanning
    'enabled' => env('SAFEGUARD_SVG_SCAN', true),

    // Additional dangerous tags to detect
    'custom_dangerous_tags' => [],

    // Tags to exclude from scanning
    'exclude_tags' => [],

    // Additional dangerous attributes to detect
    'custom_dangerous_attributes' => [],

    // Attributes to exclude from scanning
    'exclude_attributes' => [],
],
```

### Environment Variables

```env
SAFEGUARD_SVG_SCAN=true
```

### Customize Scanning

```php
'svg_scanning' => [
    // Allow SVG animations
    'exclude_tags' => [
        'animate',
        'animateTransform',
    ],

    // Allow specific attributes
    'exclude_attributes' => [
        'onload',  // If you need it
    ],

    // Add custom dangerous items
    'custom_dangerous_tags' => [
        'video',
        'audio',
    ],
    'custom_dangerous_attributes' => [
        'ontouchstart',
        'ontouchend',
    ],
],
```

---

## Image Security Scanning

### Basic Configuration

```php
'image_scanning' => [
    // Enable image security scanning
    'enabled' => env('SAFEGUARD_IMAGE_SCAN', true),

    // Check for GPS location data in EXIF
    'check_gps' => env('SAFEGUARD_IMAGE_CHECK_GPS', true),

    // Block upload if GPS found (false = warn only)
    'block_gps' => env('SAFEGUARD_IMAGE_BLOCK_GPS', false),

    // Automatically strip metadata from uploaded images
    'auto_strip_metadata' => env('SAFEGUARD_IMAGE_STRIP_META', false),

    // Suspicious EXIF tags to scan
    'suspicious_exif_tags' => [
        'Comment',
        'UserComment',
        'ImageDescription',
        'Artist',
        'Copyright',
        'Software',
    ],
],
```

### Environment Variables

```env
SAFEGUARD_IMAGE_SCAN=true
SAFEGUARD_IMAGE_CHECK_GPS=true
SAFEGUARD_IMAGE_BLOCK_GPS=false
SAFEGUARD_IMAGE_STRIP_META=false
```

### GPS Handling

```php
// Just check and log
'check_gps' => true,
'block_gps' => false,

// Block uploads with GPS
'check_gps' => true,
'block_gps' => true,

// Auto-strip all metadata (including GPS)
'auto_strip_metadata' => true,
```

### Per-Field Control

You can override config per field using rule objects:

```php
use Abdian\LaravelSafeguard\Rules\SafeguardImage;

$request->validate([
    // Block GPS for this field only
    'profile_photo' => ['required', (new SafeguardImage())->blockGps()],

    // Strip metadata for this field only
    'avatar' => ['required', (new SafeguardImage())->stripMetadata()],
]);
```

---

## PDF Security Scanning

### Basic Configuration

```php
'pdf_scanning' => [
    // Enable PDF security scanning
    'enabled' => env('SAFEGUARD_PDF_SCAN', true),

    // Additional dangerous PDF actions to detect
    'custom_dangerous_actions' => [],

    // PDF actions to exclude from scanning
    'exclude_actions' => [],
],
```

### Environment Variables

```env
SAFEGUARD_PDF_SCAN=true
```

### Customize Scanning

```php
'pdf_scanning' => [
    // Add custom dangerous actions
    'custom_dangerous_actions' => [
        '/OpenAction',
        '/AA',  // Additional Actions
    ],

    // Exclude specific actions if needed
    'exclude_actions' => [
        '/Sound',  // Allow sound in PDFs
    ],
],
```

### Per-Field Control

```php
use Abdian\LaravelSafeguard\Rules\SafeguardPdf;

$request->validate([
    // Block JavaScript for this field
    'contract' => ['required', (new SafeguardPdf())->blockJavaScript()],

    // Block external links
    'document' => ['required', (new SafeguardPdf())->blockExternalLinks()],

    // Both
    'sensitive' => ['required', (new SafeguardPdf())
        ->blockJavaScript()
        ->blockExternalLinks()
    ],
]);
```

---

## Logging & Monitoring

### Basic Configuration

```php
'logging' => [
    // Enable security event logging
    'enabled' => env('SAFEGUARD_LOGGING', true),

    // Laravel log channel to use
    'channel' => env('SAFEGUARD_LOG_CHANNEL', 'stack'),

    // Include detailed threat information
    'detailed' => env('SAFEGUARD_LOG_DETAILED', true),

    // File hash algorithm for forensics
    'hash_algorithm' => 'sha256',  // md5, sha256, or false
],
```

### Environment Variables

```env
SAFEGUARD_LOGGING=true
SAFEGUARD_LOG_CHANNEL=stack
SAFEGUARD_LOG_DETAILED=true
```

### Custom Log Channel

Create in `config/logging.php`:

```php
'channels' => [
    'security' => [
        'driver' => 'daily',
        'path' => storage_path('logs/security.log'),
        'level' => 'warning',
        'days' => 90,
    ],
],
```

Then set:

```env
SAFEGUARD_LOG_CHANNEL=security
```

See [Logging Guide](logging.md) for complete logging documentation.

---

## Complete .env Example

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

# PDF Security Scanning
SAFEGUARD_PDF_SCAN=true

# Logging
SAFEGUARD_LOGGING=true
SAFEGUARD_LOG_CHANNEL=stack
SAFEGUARD_LOG_DETAILED=true
```

---

## Performance Considerations

### Disable Unused Scanners

If you don't use certain file types, disable their scanners:

```env
# Don't upload SVGs? Disable scanner
SAFEGUARD_SVG_SCAN=false

# Don't upload PDFs? Disable scanner
SAFEGUARD_PDF_SCAN=false
```

### Disable Logging in Development

```env
# .env.local
SAFEGUARD_LOGGING=false
```

### Optimize for Production

```php
// config/safeguard.php
'php_scanning' => [
    'mode' => 'strict',  // Scan fewer functions
],

'image_scanning' => [
    'auto_strip_metadata' => true,  // Strip once, not per-request
],

'logging' => [
    'detailed' => false,  // Less verbose logs
],
```

---

## Configuration Caching

After modifying config, clear cache:

```bash
php artisan config:clear
php artisan config:cache
```

---

## Next Steps

- [Customization Guide](customization.md) — Extend functionality
- [Logging Guide](logging.md) — Security monitoring
- [Examples](examples.md) — Real-world configurations
