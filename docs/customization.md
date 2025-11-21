# Customization Guide

Extend and customize Laravel Safeguard functionality.

---

## Adding Custom File Types

Support additional file formats by adding magic bytes signatures.

### Find Magic Bytes

**Linux/Mac:**
```bash
xxd -l 16 yourfile.ext
# Output: 00000000: 8950 4e47 0d0a 1a0a 0000 000d 4948 4452  .PNG........IHDR
```

**Windows PowerShell:**
```powershell
Format-Hex -Path yourfile.ext -Count 16
```

**PHP:**
```php
$handle = fopen('file.ext', 'rb');
$bytes = fread($handle, 16);
fclose($handle);
echo bin2hex($bytes);
```

### Add to Configuration

```php
// config/safeguard.php
'mime_validation' => [
    'custom_signatures' => [
        // HEIC images (iPhone photos)
        '6674797068656963' => 'image/heic',

        // AVIF images
        '66747970617669' => 'image/avif',

        // WebP images
        '52494646' => 'image/webp',

        // Java class files
        'cafebabe' => 'application/java-vm',
    ],
],
```

### Example: Support HEIC Images

```php
// 1. Add magic bytes
'custom_signatures' => [
    '6674797068656963' => 'image/heic',
],

// 2. Use in validation
$request->validate([
    'photo' => 'required|safeguard_mime:image/heic,image/jpeg',
]);
```

---

## Customizing PHP Scanning

### Add Dangerous Functions

```php
'php_scanning' => [
    'mode' => 'default',
    'custom_dangerous_functions' => [
        'my_unsafe_function',
        'legacy_exec',
        'template_eval',
    ],
],
```

### Exclude Safe Functions

```php
'php_scanning' => [
    'exclude_functions' => [
        'file_get_contents',  // Safe in your context
        'base64_decode',      // Used for images
        'json_decode',        // Common usage
    ],
],
```

### Add Custom Patterns

```php
'php_scanning' => [
    'custom_patterns' => [
        '/backdoor/i',
        '/shell_command/i',
        '/malicious_code/i',
    ],
],
```

### Exclude Patterns

```php
'php_scanning' => [
    'exclude_patterns' => [
        '/base64_decode/i',  // Ignore base64
        '/json_encode/i',    // Ignore JSON
    ],
],
```

### Custom Scan Mode

Only scan what you specify:

```php
'php_scanning' => [
    'mode' => 'custom',
    'scan_functions' => [
        'eval',
        'exec',
        'shell_exec',
        'system',
        'passthru',
    ],
],
```

### Real-World Example

Allow file operations but block code execution:

```php
'php_scanning' => [
    'mode' => 'default',

    // Allow safe file operations
    'exclude_functions' => [
        'file_get_contents',
        'file_put_contents',
        'fopen',
        'fread',
        'fwrite',
    ],

    // Block custom dangerous functions
    'custom_dangerous_functions' => [
        'custom_exec',
        'app_shell',
    ],

    // Ignore safe patterns
    'exclude_patterns' => [
        '/\/\/ Safe: /',  // Comments marked safe
    ],
],
```

---

## Customizing SVG Scanning

### Allow Specific Tags

```php
'svg_scanning' => [
    // Allow SVG animations
    'exclude_tags' => [
        'animate',
        'animateTransform',
        'animateMotion',
        'set',
    ],
],
```

### Allow Specific Attributes

```php
'svg_scanning' => [
    'exclude_attributes' => [
        'onload',  // If you trust the source
    ],
],
```

### Add Dangerous Items

```php
'svg_scanning' => [
    'custom_dangerous_tags' => [
        'video',
        'audio',
        'foreignObject',
    ],

    'custom_dangerous_attributes' => [
        'ontouchstart',
        'ontouchend',
        'ontouchmove',
    ],
],
```

---

## Customizing Image Scanning

### Modify EXIF Tags

Scan additional or different EXIF tags:

```php
'image_scanning' => [
    'suspicious_exif_tags' => [
        'Comment',
        'UserComment',
        'ImageDescription',
        'Artist',
        'Copyright',
        'Software',
        'Make',        // Camera make
        'Model',       // Camera model
        'ProcessingSoftware',
    ],
],
```

### GPS Behavior

```php
// Option 1: Check but don't block
'image_scanning' => [
    'check_gps' => true,
    'block_gps' => false,  // Just log it
],

// Option 2: Block uploads with GPS
'image_scanning' => [
    'check_gps' => true,
    'block_gps' => true,   // Reject upload
],

// Option 3: Auto-strip all metadata
'image_scanning' => [
    'auto_strip_metadata' => true,  // Remove everything
],
```

---

## Customizing PDF Scanning

### Add Dangerous Actions

```php
'pdf_scanning' => [
    'custom_dangerous_actions' => [
        '/OpenAction',     // Auto-execute on open
        '/AA',             // Additional Actions
        '/Names',          // Named actions
        '/AcroForm',       // Interactive forms
    ],
],
```

### Allow Specific Actions

```php
'pdf_scanning' => [
    // Allow these if needed
    'exclude_actions' => [
        '/URI',      // External links (if you trust source)
        '/Sound',    // Audio in PDFs
        '/Movie',    // Video in PDFs
    ],
],
```

---

## Creating Custom Scanners

Create your own scanner for specific file types.

### 1. Create Scanner Class

```php
<?php

namespace App\Security\Scanners;

use Illuminate\Http\UploadedFile;

class DocxScanner
{
    public function scan(UploadedFile $file): array
    {
        $path = $file->getRealPath();

        // Your scanning logic
        $threats = [];

        // Check for macros
        if ($this->hasMacros($path)) {
            $threats[] = 'Macros detected in document';
        }

        return [
            'safe' => empty($threats),
            'threats' => $threats,
        ];
    }

    protected function hasMacros(string $path): bool
    {
        // Implementation
        return false;
    }
}
```

### 2. Create Validation Rule

```php
<?php

namespace App\Rules;

use App\Security\Scanners\DocxScanner;
use Closure;
use Illuminate\Contracts\Validation\ValidationRule;
use Illuminate\Http\UploadedFile;

class SafeguardDocx implements ValidationRule
{
    protected DocxScanner $scanner;

    public function __construct()
    {
        $this->scanner = new DocxScanner();
    }

    public function validate(string $attribute, mixed $value, Closure $fail): void
    {
        if (!$value instanceof UploadedFile) {
            $fail("The {$attribute} must be a valid file.");
            return;
        }

        $result = $this->scanner->scan($value);

        if (!$result['safe']) {
            $fail("The {$attribute} contains threats: " . implode(', ', $result['threats']));
        }
    }
}
```

### 3. Use in Validation

```php
use App\Rules\SafeguardDocx;

$request->validate([
    'document' => ['required', 'mimes:docx', new SafeguardDocx()],
]);
```

---

## Extending Existing Scanners

Extend built-in scanners to add custom logic.

### Example: Extend MimeTypeDetector

```php
<?php

namespace App\Security;

use Abdian\LaravelSafeguard\MimeTypeDetector as BaseMimeTypeDetector;

class CustomMimeTypeDetector extends BaseMimeTypeDetector
{
    protected array $magicBytes = [
        // Add parent signatures
        ...parent::$magicBytes ?? [],

        // Add your signatures
        '6674797068656963' => 'image/heic',
        '66747970617669' => 'image/avif',
    ];

    public function detect($file): ?string
    {
        $result = parent::detect($file);

        // Add custom logic
        if ($result === 'application/octet-stream') {
            // Try alternative detection
            $result = $this->alternativeDetection($file);
        }

        return $result;
    }

    protected function alternativeDetection($file): ?string
    {
        // Your custom detection logic
        return null;
    }
}
```

### Use Custom Scanner

```php
use App\Security\CustomMimeTypeDetector;
use Abdian\LaravelSafeguard\Rules\SafeguardMime;

$detector = new CustomMimeTypeDetector();
$mimeType = $detector->detect($file);
```

---

## Custom Error Messages

### Global Messages

In your language files (`lang/en/validation.php`):

```php
'custom' => [
    'avatar' => [
        'safeguard' => 'Your profile photo contains malicious content.',
        'safeguard_mime' => 'Please upload a valid image file (JPEG or PNG).',
        'safeguard_dimensions' => 'Image must be between 200x200 and 1920x1080 pixels.',
    ],
],
```

### Per-Request Messages

```php
$request->validate([
    'avatar' => 'required|safeguard',
], [
    'avatar.safeguard' => 'Your profile photo failed security checks. Please try a different image.',
]);
```

### Form Request Messages

```php
class UploadFileRequest extends FormRequest
{
    public function messages(): array
    {
        return [
            'avatar.safeguard' => 'Security check failed. Please upload a safe image.',
            'document.safeguard_pdf' => 'PDF contains malicious content.',
        ];
    }
}
```

---

## Allow Dangerous Files Per Field

Sometimes you need to allow dangerous file types for specific use cases.

```php
use Abdian\LaravelSafeguard\Rules\SafeguardMime;

$request->validate([
    // Normal files - block dangerous
    'upload' => 'required|safeguard_mime:image/*',

    // Admin upload - allow JavaScript
    'script' => ['required', (new SafeguardMime(['application/javascript']))->allowDangerous()],
]);
```

---

## Integration with Other Packages

### With Spatie Media Library

```php
use Spatie\MediaLibrary\MediaCollections\Models\Media;
use Abdian\LaravelSafeguard\Rules\Safeguard;

public function addMediaFromRequest($field)
{
    $validated = request()->validate([
        $field => ['required', new Safeguard()],
    ]);

    $this->addMedia(request()->file($field))
        ->toMediaCollection();
}
```

### With Laravel Livewire

```php
use Livewire\Component;
use Livewire\WithFileUploads;
use Abdian\LaravelSafeguard\Rules\Safeguard;

class UploadFile extends Component
{
    use WithFileUploads;

    public $file;

    public function save()
    {
        $this->validate([
            'file' => ['required', new Safeguard()],
        ]);

        $this->file->store('uploads');
    }
}
```

---

## Next Steps

- [Configuration Guide](configuration.md) — Complete config reference
- [Advanced Usage](advanced.md) — Complex scenarios
- [Examples](examples.md) — Real-world implementations
