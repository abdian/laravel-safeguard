# Laravel Safeguard - Improvement Roadmap

This document outlines all planned improvements, bug fixes, and feature additions for the Laravel Safeguard package, organized by priority.

---

## Priority 1: Critical Security Fixes

### 1.1 XXE Protection in SVG/XML Parsing
**Status:** `[ ] Pending`
**Severity:** Critical
**File:** `src/SvgScanner.php`

**Problem:**
SVG and XML parsing doesn't disable external entity loading, allowing XXE (XML External Entity) attacks that could cause DoS or file disclosure.

**Solution:**
```php
// Add before any XML parsing
libxml_disable_entity_loader(true);
$previousValue = libxml_use_internal_errors(true);
```

**Attack Example:**
```xml
<?xml version="1.0"?>
<!DOCTYPE svg [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<svg>&xxe;</svg>
```

---

### 1.2 Archive Content Scanning (ZIP/RAR/7Z)
**Status:** `[ ] Pending`
**Severity:** Critical
**Files:** New `src/ArchiveScanner.php`

**Problem:**
Archive files (ZIP, RAR, 7Z, TAR) are detected by MIME type but their contents are not scanned. Attackers can upload archives containing malware, PHP shells, or executables.

**Solution:**
Create `ArchiveScanner` class that:
- Opens archive safely
- Lists all files inside
- Checks for dangerous extensions (.php, .exe, .bat, .sh, .phar)
- Checks for path traversal attempts (../)
- Validates nested archives (max depth)
- Detects zip bombs (compression ratio check)

**Features:**
```php
class ArchiveScanner {
    public function scan(UploadedFile $file): array;
    public function setMaxDepth(int $depth): self;
    public function setMaxFiles(int $count): self;
    public function setMaxUncompressedSize(int $bytes): self;
    public function setBlockedExtensions(array $extensions): self;
}
```

---

### 1.3 Office Document Macro Detection
**Status:** `[ ] Pending`
**Severity:** Critical
**Files:** New `src/OfficeScanner.php`

**Problem:**
DOCX/XLSX/PPTX files can contain VBA macros which are a known attack vector for malware distribution.

**Solution:**
Create `OfficeScanner` class that:
- Opens Office Open XML files as ZIP
- Checks for `vbaProject.bin` file (indicates macros)
- Checks for macro-enabled content types in `[Content_Types].xml`
- Detects `.docm`, `.xlsm`, `.pptm` disguised as `.docx`, `.xlsx`, `.pptx`

**Detection Logic:**
```php
// Check [Content_Types].xml for macro indicators
$macroTypes = [
    'application/vnd.ms-office.vbaProject',
    'application/vnd.ms-word.document.macroEnabled',
    'application/vnd.ms-excel.sheet.macroEnabled',
];
```

---

### 1.4 Symlink/Hardlink Validation
**Status:** `[ ] Pending`
**Severity:** High
**Files:** All scanner classes

**Problem:**
Scanners don't check if uploaded file is a symlink to system files, enabling TOCTOU (time-of-check-time-of-use) attacks.

**Solution:**
Add validation before scanning:
```php
protected function validateFileAccess(string $path): bool
{
    // Reject symlinks
    if (is_link($path)) {
        return false;
    }

    // Ensure file is in expected upload directory
    $realPath = realpath($path);
    $uploadDir = realpath(sys_get_temp_dir());

    return str_starts_with($realPath, $uploadDir);
}
```

---

### 1.5 Zip Bomb Detection
**Status:** `[ ] Pending`
**Severity:** High
**Files:** `src/ArchiveScanner.php`

**Problem:**
Highly compressed archives can expand to enormous sizes, consuming all disk space and memory.

**Solution:**
```php
protected function isZipBomb(string $path): bool
{
    $zip = new ZipArchive();
    $zip->open($path);

    $compressedSize = filesize($path);
    $uncompressedSize = 0;

    for ($i = 0; $i < $zip->numFiles; $i++) {
        $stat = $zip->statIndex($i);
        $uncompressedSize += $stat['size'];
    }

    $ratio = $uncompressedSize / $compressedSize;

    // Ratio > 100:1 is suspicious
    return $ratio > 100;
}
```

---

## Priority 2: Performance Optimizations

### 2.1 MIME Detection Caching
**Status:** `[ ] Pending`
**Severity:** Medium
**Files:** `src/Rules/Safeguard.php`, `src/MimeTypeDetector.php`

**Problem:**
MIME type is detected multiple times for the same file during validation, causing redundant file I/O.

**Solution:**
Cache detected MIME type:
```php
class MimeTypeDetector
{
    protected static array $cache = [];

    public function detect(UploadedFile|string $file): ?string
    {
        $path = $file instanceof UploadedFile ? $file->getRealPath() : $file;
        $cacheKey = $path . ':' . filemtime($path);

        if (isset(self::$cache[$cacheKey])) {
            return self::$cache[$cacheKey];
        }

        $mimeType = $this->doDetect($path);
        self::$cache[$cacheKey] = $mimeType;

        return $mimeType;
    }
}
```

---

### 2.2 Refactor ServiceProvider (Remove Duplication)
**Status:** `[ ] Pending`
**Severity:** Medium
**Files:** `src/SafeguardServiceProvider.php`

**Problem:**
~230 lines of repetitive code for registering validation rules.

**Current Code (repeated 8 times):**
```php
Validator::extend('safeguard_xxx', function ($attribute, $value, $parameters, $validator) {
    $rule = new SafeguardXxx();
    $fails = false;
    $errorMessage = '';
    $rule->validate($attribute, $value, function ($message) use (&$fails, &$errorMessage) {
        $fails = true;
        $errorMessage = $message;
    });
    if ($fails) {
        $validator->addReplacer('safeguard_xxx', function () use ($errorMessage) {
            return $errorMessage;
        });
        return false;
    }
    return true;
});
Validator::replacer('safeguard_xxx', fn($msg) => $msg);
```

**Solution:**
```php
protected function registerValidationRules(): void
{
    $rules = [
        'safeguard' => fn($params) => new Safeguard(),
        'safeguard_mime' => fn($params) => new SafeguardMime($params),
        'safeguard_php' => fn($params) => new SafeguardPhp(),
        'safeguard_svg' => fn($params) => new SafeguardSvg(),
        'safeguard_image' => fn($params) => new SafeguardImage(),
        'safeguard_pdf' => fn($params) => new SafeguardPdf(),
        'safeguard_dimensions' => fn($params) => new SafeguardDimensions(...$params),
        'safeguard_pages' => fn($params) => new SafeguardPages(...$params),
    ];

    foreach ($rules as $ruleName => $ruleFactory) {
        $this->registerRule($ruleName, $ruleFactory);
    }
}

protected function registerRule(string $ruleName, callable $ruleFactory): void
{
    Validator::extend($ruleName, function ($attribute, $value, $parameters, $validator) use ($ruleName, $ruleFactory) {
        $rule = $ruleFactory($parameters);
        $fails = false;
        $errorMessage = '';

        $rule->validate($attribute, $value, function ($message) use (&$fails, &$errorMessage) {
            $fails = true;
            $errorMessage = $message;
        });

        if ($fails) {
            $validator->addReplacer($ruleName, fn() => $errorMessage);
            return false;
        }
        return true;
    });

    Validator::replacer($ruleName, fn($msg) => $msg);
}
```

---

### 2.3 Memory Management for Large PDFs
**Status:** `[ ] Pending`
**Severity:** Medium
**Files:** `src/PdfScanner.php`

**Problem:**
`file_get_contents()` loads entire PDF into memory. Large PDFs (100MB+) can cause memory exhaustion.

**Solution:**
```php
public function scan(UploadedFile|string $file): array
{
    $path = $file instanceof UploadedFile ? $file->getRealPath() : $file;

    // Check file size before reading
    $maxSize = $this->getConfig('safeguard.pdf_scanning.max_scan_size', 50 * 1024 * 1024); // 50MB
    $fileSize = filesize($path);

    if ($fileSize > $maxSize) {
        return [
            'safe' => false,
            'threats' => ['File too large to scan safely'],
            'has_javascript' => false,
            'has_external_links' => false,
        ];
    }

    // Continue with normal scanning...
}
```

---

### 2.4 Pre-compile Regex Patterns
**Status:** `[ ] Pending`
**Severity:** Medium
**Files:** `src/PhpCodeScanner.php`

**Problem:**
Regex patterns are compiled inside loops, causing 70+ compilations per file.

**Solution:**
```php
class PhpCodeScanner
{
    protected static ?array $compiledPatterns = null;

    protected function getCompiledPatterns(): array
    {
        if (self::$compiledPatterns === null) {
            $functions = $this->buildFunctionsList();
            self::$compiledPatterns = array_map(
                fn($func) => '/\b' . preg_quote($func, '/') . '\s*\(/i',
                $functions
            );
        }
        return self::$compiledPatterns;
    }
}
```

---

### 2.5 Video/Audio Metadata Scanning
**Status:** `[ ] Pending`
**Severity:** Medium
**Files:** New `src/MediaScanner.php`

**Problem:**
Only image EXIF metadata is scanned. Video and audio files can also embed malicious scripts in metadata.

**Solution:**
Create `MediaScanner` class using FFmpeg or getID3 library:
```php
class MediaScanner
{
    public function scan(UploadedFile|string $file): array
    {
        // Check for embedded scripts in metadata
        // Check for suspicious embedded streams
        // Validate codec information
    }
}
```

---

## Priority 3: New Features

### 3.1 Event/Hook System
**Status:** `[ ] Pending`
**Severity:** Medium
**Files:** New `src/Events/` directory

**Problem:**
Users cannot hook into scanning lifecycle for custom actions (logging, notifications, etc.).

**Solution:**
Create Laravel events:
```php
// src/Events/FileScanning.php
class FileScanning
{
    public function __construct(
        public UploadedFile $file,
        public string $attribute,
    ) {}
}

// src/Events/FileScanned.php
class FileScanned
{
    public function __construct(
        public UploadedFile $file,
        public string $attribute,
        public bool $passed,
        public array $threats = [],
    ) {}
}

// src/Events/ThreatDetected.php
class ThreatDetected
{
    public function __construct(
        public UploadedFile $file,
        public string $attribute,
        public array $threats,
        public string $scannerClass,
    ) {}
}
```

**Usage:**
```php
// In AppServiceProvider or EventServiceProvider
Event::listen(ThreatDetected::class, function ($event) {
    Log::critical('Threat detected', [
        'file' => $event->file->getClientOriginalName(),
        'threats' => $event->threats,
    ]);

    // Notify security team
    Notification::send($securityTeam, new ThreatNotification($event));
});
```

---

### 3.2 Quarantine Directory
**Status:** `[ ] Pending`
**Severity:** Low
**Files:** `src/config/safeguard.php`, `src/SecurityLogger.php`

**Problem:**
Rejected files are discarded without option for forensic analysis.

**Solution:**
Add configuration:
```php
// config/safeguard.php
'quarantine' => [
    'enabled' => env('SAFEGUARD_QUARANTINE', false),
    'path' => storage_path('safeguard/quarantine'),
    'max_size' => 100 * 1024 * 1024, // 100MB total
    'retention_days' => 30,
],
```

Add quarantine logic:
```php
class SecurityLogger
{
    public static function quarantineFile(UploadedFile $file, array $threats): ?string
    {
        if (!config('safeguard.quarantine.enabled')) {
            return null;
        }

        $quarantinePath = config('safeguard.quarantine.path');
        $filename = date('Y-m-d_His') . '_' . hash('sha256', $file->getClientOriginalName()) . '.quarantine';

        $metadata = [
            'original_name' => $file->getClientOriginalName(),
            'mime_type' => $file->getMimeType(),
            'threats' => $threats,
            'uploaded_at' => now()->toIso8601String(),
            'ip' => request()->ip(),
            'user_id' => auth()->id(),
        ];

        // Save file
        copy($file->getRealPath(), "$quarantinePath/$filename");
        file_put_contents("$quarantinePath/$filename.json", json_encode($metadata, JSON_PRETTY_PRINT));

        return "$quarantinePath/$filename";
    }
}
```

---

### 3.3 Artisan Commands
**Status:** `[ ] Pending`
**Severity:** Low
**Files:** New `src/Console/` directory

**Commands to add:**

```php
// php artisan safeguard:rules
class ListRulesCommand extends Command
{
    protected $signature = 'safeguard:rules';
    protected $description = 'List all available Safeguard validation rules';

    public function handle()
    {
        $this->table(['Rule', 'Parameters', 'Description'], [
            ['safeguard', '-', 'Comprehensive security check'],
            ['safeguard_mime', 'mime1,mime2,...', 'Validate MIME type'],
            ['safeguard_php', '-', 'Scan for PHP code'],
            ['safeguard_svg', '-', 'Scan SVG for XSS'],
            ['safeguard_image', '-', 'Scan image metadata'],
            ['safeguard_pdf', '-', 'Scan PDF for threats'],
            ['safeguard_dimensions', 'max_w,max_h[,min_w,min_h]', 'Validate image dimensions'],
            ['safeguard_pages', 'min,max', 'Validate PDF page count'],
        ]);
    }
}

// php artisan safeguard:scan {file}
class ScanFileCommand extends Command
{
    protected $signature = 'safeguard:scan {file} {--json}';
    protected $description = 'Scan a file for security threats';
}

// php artisan safeguard:quarantine:clean
class CleanQuarantineCommand extends Command
{
    protected $signature = 'safeguard:quarantine:clean {--days=30}';
    protected $description = 'Clean old quarantined files';
}
```

---

### 3.4 Rate Limiting for Scanning
**Status:** `[ ] Pending`
**Severity:** Medium
**Files:** `src/Rules/Safeguard.php`, `src/config/safeguard.php`

**Problem:**
No protection against DoS via large file uploads triggering expensive scanning operations.

**Solution:**
```php
// config/safeguard.php
'rate_limiting' => [
    'enabled' => env('SAFEGUARD_RATE_LIMIT', true),
    'max_file_size' => 50 * 1024 * 1024, // 50MB
    'max_files_per_minute' => 10,
    'max_total_size_per_minute' => 100 * 1024 * 1024, // 100MB
],
```

---

### 3.5 WebAssembly Support
**Status:** `[ ] Pending`
**Severity:** Low
**Files:** `src/MimeTypeDetector.php`, `src/ExtensionMimeMap.php`

**Problem:**
WebAssembly (.wasm) files not detected.

**Solution:**
```php
// MimeTypeDetector.php - add to $magicBytes
'0061736d' => 'application/wasm', // \0asm

// ExtensionMimeMap.php - add mapping
'wasm' => ['application/wasm'],
```

---

## Priority 4: Code Quality & Testing

### 4.1 Comprehensive Test Suite
**Status:** `[ ] Pending`
**Severity:** High
**Files:** `tests/` directory

**Current State:**
- Only 1 test file: `MimeTypeDetectorTest.php`
- 15 tests, 25 assertions

**Required Tests:**

```
tests/
├── Unit/
│   ├── MimeTypeDetectorTest.php      ✅ Exists
│   ├── ExtensionMimeMapTest.php      ❌ Missing
│   ├── PhpCodeScannerTest.php        ❌ Missing
│   ├── SvgScannerTest.php            ❌ Missing
│   ├── ImageScannerTest.php          ❌ Missing
│   ├── PdfScannerTest.php            ❌ Missing
│   ├── ArchiveScannerTest.php        ❌ Missing (new)
│   ├── OfficeScannerTest.php         ❌ Missing (new)
│   └── SecurityLoggerTest.php        ❌ Missing
├── Rules/
│   ├── SafeguardTest.php             ❌ Missing
│   ├── SafeguardMimeTest.php         ❌ Missing
│   ├── SafeguardPhpTest.php          ❌ Missing
│   ├── SafeguardSvgTest.php          ❌ Missing
│   ├── SafeguardImageTest.php        ❌ Missing
│   ├── SafeguardPdfTest.php          ❌ Missing
│   ├── SafeguardDimensionsTest.php   ❌ Missing
│   └── SafeguardPagesTest.php        ❌ Missing
├── Integration/
│   ├── LaravelValidationTest.php     ❌ Missing
│   ├── MultipleFileUploadTest.php    ❌ Missing
│   └── ConfigurationTest.php         ❌ Missing
├── Security/
│   ├── XxeAttackTest.php             ❌ Missing
│   ├── PolyglotFileTest.php          ❌ Missing
│   ├── ZipBombTest.php               ❌ Missing
│   └── PathTraversalTest.php         ❌ Missing
└── Performance/
    ├── LargeFileTest.php             ❌ Missing
    └── MemoryUsageTest.php           ❌ Missing
```

---

### 4.2 Exception Handling Improvement
**Status:** `[ ] Pending`
**Severity:** Medium
**Files:** All scanner classes

**Problem:**
Using `@` error suppression and generic try-catch masks legitimate errors.

**Solution:**
Create custom exceptions:
```php
// src/Exceptions/SafeguardException.php
class SafeguardException extends Exception {}

// src/Exceptions/FileReadException.php
class FileReadException extends SafeguardException {}

// src/Exceptions/ScannerException.php
class ScannerException extends SafeguardException {}

// src/Exceptions/ConfigurationException.php
class ConfigurationException extends SafeguardException {}
```

---

### 4.3 Configuration Validation
**Status:** `[ ] Pending`
**Severity:** Low
**Files:** `src/SafeguardServiceProvider.php`

**Problem:**
Invalid config values silently default without warning.

**Solution:**
```php
public function boot(): void
{
    $this->validateConfiguration();
    // ...
}

protected function validateConfiguration(): void
{
    $mode = config('safeguard.php_scanning.mode');
    if (!in_array($mode, ['default', 'strict', 'custom'])) {
        throw new ConfigurationException(
            "Invalid php_scanning.mode: '$mode'. Must be 'default', 'strict', or 'custom'."
        );
    }

    // Validate other config values...
}
```

---

### 4.4 PHPStan/Psalm Static Analysis
**Status:** `[ ] Pending`
**Severity:** Low
**Files:** `phpstan.neon`, all PHP files

**Problem:**
Incomplete type hints reduce IDE support and miss potential bugs.

**Solution:**
1. Add `phpstan.neon`:
```neon
parameters:
    level: 8
    paths:
        - src
    ignoreErrors: []
```

2. Add to `composer.json`:
```json
"require-dev": {
    "phpstan/phpstan": "^1.0"
}
```

3. Fix all type hints to use full PHPDoc:
```php
/**
 * @param array<string> $extensions
 * @return array<string, array<string>>
 */
```

---

## Priority 5: Documentation

### 5.1 Migration Guide
**Status:** `[ ] Pending`
**Files:** `docs/migration.md`

**Content:**
- How to migrate from vanilla `mimes` rule
- How to add safeguard to existing projects
- Configuration options explained
- Common issues and solutions

---

### 5.2 Security Best Practices Guide
**Status:** `[ ] Pending`
**Files:** `docs/security.md`

**Content:**
- Recommended configuration for production
- How to handle different file types
- Logging and monitoring recommendations
- Incident response procedures

---

### 5.3 API Reference
**Status:** `[ ] Pending`
**Files:** `docs/api.md`

**Content:**
- All classes and methods documented
- Parameters and return types
- Code examples for each feature

---

## Changelog

| Date | Version | Changes |
|------|---------|---------|
| 2024-XX-XX | 1.x.x | Initial roadmap created |

---

## Contributing

If you'd like to contribute to any of these improvements:

1. Pick an item from this list
2. Create a branch: `feature/item-name` or `fix/item-name`
3. Implement with tests
4. Submit PR referencing this document

---

## Notes

- Items marked `[ ]` are pending
- Items marked `[x]` are completed
- Priority 1 items should be completed before any new releases
- All new features require corresponding tests
