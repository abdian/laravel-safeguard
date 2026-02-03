# Configuration

Customize Laravel Safeguard settings.

## Publish Config

```bash
php artisan vendor:publish --tag=safeguard-config
```

This creates `config/safeguard.php`.

---

## MIME Type Validation

```php
'mime_validation' => [
    // Fail if detected MIME type doesn't match client-provided type
    'strict_check' => true,

    // Automatically block dangerous file types (executables, scripts)
    'block_dangerous' => true,

    // Custom magic bytes signatures
    'custom_signatures' => [
        // 'cafebabe' => 'application/java-vm',
    ],

    // Dangerous MIME types to block
    'dangerous_types' => [
        'application/x-msdownload',    // Windows .exe
        'application/x-php',           // PHP files
        'text/x-shellscript',          // Shell scripts
        // ... more
    ],
],
```

---

## PHP Code Scanning

```php
'php_scanning' => [
    // Enable PHP code scanning
    'enabled' => true,

    // Scan mode: 'default', 'strict', 'custom'
    'mode' => 'default',

    // Functions to scan for (custom mode)
    'scan_functions' => [],

    // Additional dangerous functions
    'custom_dangerous_functions' => [],

    // Functions to exclude from scanning
    'exclude_functions' => [],

    // Additional suspicious patterns (regex)
    'custom_patterns' => [],

    // Patterns to exclude
    'exclude_patterns' => [],
],
```

---

## SVG Security Scanning

```php
'svg_scanning' => [
    // Enable SVG security scanning
    'enabled' => true,

    // Additional dangerous tags to detect
    'custom_dangerous_tags' => [],

    // Tags to exclude from scanning
    'exclude_tags' => [],

    // Additional dangerous attributes
    'custom_dangerous_attributes' => [],

    // Attributes to exclude
    'exclude_attributes' => [],
],
```

---

## Image Security Scanning

```php
'image_scanning' => [
    // Enable image security scanning
    'enabled' => true,

    // Check for GPS location data in EXIF
    'check_gps' => true,

    // Block uploads with GPS data
    'block_gps' => false,

    // Automatically strip metadata
    'auto_strip_metadata' => false,

    // Suspicious EXIF tags to scan
    'suspicious_exif_tags' => [
        'Comment', 'UserComment', 'ImageDescription',
        'Artist', 'Copyright', 'Software',
    ],
],
```

---

## PDF Security Scanning

```php
'pdf_scanning' => [
    // Enable PDF security scanning
    'enabled' => true,

    // Additional dangerous PDF actions
    'custom_dangerous_actions' => [],

    // PDF actions to exclude
    'exclude_actions' => [],
],
```

---

## Archive Scanning

```php
'archive_scanning' => [
    // Enable archive content scanning
    'enabled' => false,

    // Maximum compression ratio (zip bomb detection)
    // Ratio 100 means 100:1 (1MB compressed = 100MB uncompressed)
    'max_compression_ratio' => 100,

    // Maximum total uncompressed size (bytes)
    'max_uncompressed_size' => 500 * 1024 * 1024, // 500MB

    // Maximum number of files in archive
    'max_files_count' => 10000,

    // Maximum nesting depth for nested archives
    'max_nesting_depth' => 3,

    // File extensions to block inside archives
    'blocked_extensions' => [
        'php', 'phar', 'exe', 'bat', 'sh', 'cmd', 'ps1',
    ],

    // Extensions to allow (overrides blocked list)
    'exclude_extensions' => [],

    // How to handle RAR files without rar extension
    // true = allow file through, false = reject
    'rar_fail_open' => false,
],
```

### Zip Bomb Detection

The `max_compression_ratio` setting protects against zip bombs. A zip bomb is a malicious archive that expands to an enormous size when extracted.

Example: A 42KB zip file that expands to 4.5 petabytes (42.zip).

```php
// Strict: block anything over 50:1 ratio
'max_compression_ratio' => 50,

// Relaxed: allow up to 200:1 ratio
'max_compression_ratio' => 200,
```

---

## Office Document Scanning

```php
'office_scanning' => [
    // Enable Office document scanning
    'enabled' => true,

    // Block documents containing VBA macros
    'block_macros' => true,

    // Block documents containing ActiveX controls
    'block_activex' => true,

    // Extensions allowed to contain macros
    // Documents with these extensions won't trigger "disguised" warnings
    'allowed_macro_extensions' => ['docm', 'xlsm', 'pptm'],
],
```

### What Gets Detected

| Feature | Description |
|---------|-------------|
| VBA Macros | `vbaProject.bin` files in document |
| Content Types | Macro indicators in `[Content_Types].xml` |
| ActiveX | ActiveX controls and OLE objects |
| Spoofing | `.docm` disguised as `.docx` |

---

## Security Settings

```php
'security' => [
    // Check for symbolic links (TOCTOU protection)
    'check_symlinks' => true,

    // Allowed upload paths (null = auto-detect)
    // Auto-detect uses: sys_get_temp_dir() + storage_path('app')
    'allowed_upload_paths' => null,

    // Or specify custom paths:
    // 'allowed_upload_paths' => [
    //     '/var/www/uploads',
    //     '/tmp',
    // ],
],
```

### Symlink Protection

Symlink checking prevents TOCTOU (Time-of-Check-Time-of-Use) attacks where an attacker:

1. Uploads a legitimate file
2. Validation passes
3. Replaces file with symlink to `/etc/passwd`
4. Application reads sensitive data

---

## Logging & Reporting

```php
'logging' => [
    // Enable security event logging
    'enabled' => true,

    // Laravel log channel
    'channel' => 'stack',

    // Include detailed threat information
    'detailed' => true,

    // File hash algorithm (md5, sha256, or false)
    'hash_algorithm' => 'sha256',
],
```

### Log Events

| Event | Description |
|-------|-------------|
| `mime_mismatch` | Detected MIME doesn't match extension |
| `dangerous_file` | Blocked dangerous file type |
| `php_code` | PHP code detected in upload |
| `svg_xss` | XSS detected in SVG |
| `xxe_detected` | XXE attack detected |
| `archive_threat` | Threat in archive contents |
| `macro_detected` | VBA macro detected |
| `symlink_detected` | Symlink upload blocked |
| `zipbomb_detected` | Zip bomb detected |

---

## Environment Variables

```env
# General
SAFEGUARD_MIME_STRICT=true
SAFEGUARD_MIME_BLOCK_DANGEROUS=true

# Scanning
SAFEGUARD_PHP_SCAN=true
SAFEGUARD_SVG_SCAN=true
SAFEGUARD_IMAGE_SCAN=true
SAFEGUARD_PDF_SCAN=true
SAFEGUARD_ARCHIVE_SCAN=false
SAFEGUARD_OFFICE_SCAN=true

# Image settings
SAFEGUARD_IMAGE_CHECK_GPS=true
SAFEGUARD_IMAGE_BLOCK_GPS=false
SAFEGUARD_IMAGE_STRIP_META=false

# Office settings
SAFEGUARD_BLOCK_MACROS=true
SAFEGUARD_BLOCK_ACTIVEX=true

# Security
SAFEGUARD_CHECK_SYMLINKS=true

# Logging
SAFEGUARD_LOGGING=true
SAFEGUARD_LOG_CHANNEL=stack
SAFEGUARD_LOG_DETAILED=true
```

---

## Next Steps

- [Validation Rules](/guide/rules) - Use the rules
- [Security Features](/guide/security) - Detailed security info
- [API Reference](/api/) - Complete reference
