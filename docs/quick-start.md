# Quick Start Guide

Get started with Laravel Safeguard in 5 minutes.

---

## 1. Basic File Upload Security

The simplest way to secure file uploads:

```php
use Illuminate\Http\Request;

public function upload(Request $request)
{
    $validated = $request->validate([
        'file' => 'required|file|safeguard',
    ]);

    // File is safe - store it
    $path = $request->file('file')->store('uploads');

    return response()->json(['path' => $path]);
}
```

**That's it!** The `safeguard` rule performs:
- Real MIME type detection
- Malware scanning (PHP, XSS)
- Metadata analysis
- Automatic dangerous file blocking

---

## 2. Image Uploads

Secure image uploads with additional validation:

```php
$request->validate([
    'avatar' => 'required|image|max:2048|safeguard',
]);
```

### Remove GPS and Metadata

```php
use Abdian\LaravelSafeguard\Rules\Safeguard;

$request->validate([
    'avatar' => ['required', (new Safeguard())
        ->imagesOnly()
        ->blockGps()
        ->stripMetadata()
        ->maxDimensions(1920, 1080)
    ],
]);
```

---

## 3. PDF Uploads

Secure PDF files:

```php
$request->validate([
    'document' => 'required|mimes:pdf|safeguard',
]);
```

### Block JavaScript in PDFs

```php
use Abdian\LaravelSafeguard\Rules\Safeguard;

$request->validate([
    'contract' => ['required', (new Safeguard())
        ->pdfsOnly()
        ->blockJavaScript()
        ->blockExternalLinks()
        ->maxPages(50)
    ],
]);
```

---

## 4. Multiple File Types

Allow specific types with security:

```php
use Abdian\LaravelSafeguard\Rules\Safeguard;

$request->validate([
    'attachment' => ['required', (new Safeguard())
        ->allowedMimes([
            'image/jpeg',
            'image/png',
            'application/pdf',
        ])
        ->maxDimensions(3000, 3000)
        ->maxPages(100)
    ],
]);
```

---

## 5. Individual Security Rules

For granular control, use specific rules:

### MIME Type Validation

```php
$request->validate([
    'avatar' => 'required|safeguard_mime:image/jpeg,image/png',
    'any_image' => 'required|safeguard_mime:image/*',
]);
```

### PHP Code Scanning

```php
$request->validate([
    'template' => 'required|safeguard_php',
]);
```

### SVG Security

```php
$request->validate([
    'icon' => 'required|safeguard_svg',
]);
```

### Image Security

```php
$request->validate([
    'photo' => 'required|safeguard_image',
]);
```

### PDF Security

```php
$request->validate([
    'document' => 'required|safeguard_pdf',
]);
```

### Dimensions & Pages

```php
$request->validate([
    'avatar' => 'required|safeguard_dimensions:1920,1080',
    'document' => 'required|safeguard_pages:1,10',
]);
```

---

## 6. Combine Multiple Rules

Stack rules for maximum security:

```php
$request->validate([
    'avatar' => [
        'required',
        'image',
        'max:5120',  // 5MB
        'safeguard_mime:image/jpeg,image/png',
        'safeguard_php',
        'safeguard_image',
        'safeguard_dimensions:1920,1080,200,200',
    ],
]);
```

Or use the all-in-one approach:

```php
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

## 7. Form Request Validation

Create a Form Request:

```php
php artisan make:request UploadFileRequest
```

```php
namespace App\Http\Requests;

use Illuminate\Foundation\Http\FormRequest;
use Abdian\LaravelSafeguard\Rules\Safeguard;

class UploadFileRequest extends FormRequest
{
    public function rules(): array
    {
        return [
            'avatar' => ['required', (new Safeguard())
                ->imagesOnly()
                ->maxDimensions(1920, 1080)
                ->blockGps()
                ->stripMetadata()
            ],
            'document' => ['required', (new Safeguard())
                ->pdfsOnly()
                ->maxPages(50)
                ->blockJavaScript()
            ],
        ];
    }

    public function messages(): array
    {
        return [
            'avatar.required' => 'Please upload your profile photo.',
            'document.required' => 'Contract document is required.',
        ];
    }
}
```

Use in controller:

```php
public function upload(UploadFileRequest $request)
{
    // Files are already validated
    $avatarPath = $request->file('avatar')->store('avatars');
    $docPath = $request->file('document')->store('documents');

    return response()->json([
        'avatar' => $avatarPath,
        'document' => $docPath,
    ]);
}
```

---

## Next Steps

- [All Validation Rules](validation-rules.md)
- [Configuration Options](configuration.md)
- [Customization Guide](customization.md)
- [Real-World Examples](examples.md)
