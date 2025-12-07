# Basic Usage

## The Safeguard Rule

The `safeguard` rule is the recommended way to secure file uploads. It runs all security checks in one go:

```php
use Illuminate\Http\Request;

public function upload(Request $request)
{
    $request->validate([
        'file' => 'required|safeguard',
    ]);

    // File is safe - proceed with storage
    $path = $request->file('file')->store('uploads');
}
```

## Using the Rule Class

For more control, use the `Safeguard` rule class with fluent methods:

```php
use Abdian\LaravelSafeguard\Rules\Safeguard;

$request->validate([
    'avatar' => ['required', (new Safeguard())
        ->imagesOnly()
        ->maxDimensions(1920, 1080)
        ->blockGps()
        ->stripMetadata()
    ],
]);
```

## Common Scenarios

### Images Only

```php
'avatar' => ['required', (new Safeguard())->imagesOnly()],
```

This allows any image format (JPEG, PNG, GIF, etc.) while blocking all non-image files.

### PDFs Only

```php
'document' => ['required', (new Safeguard())->pdfsOnly()],
```

### Documents Only

```php
'file' => ['required', (new Safeguard())->documentsOnly()],
```

Allows: PDF, DOC, DOCX, XLS, XLSX

### Specific MIME Types

```php
'file' => ['required', (new Safeguard())
    ->allowedMimes(['image/jpeg', 'image/png', 'application/pdf'])
],
```

### Image Dimensions

```php
'photo' => ['required', (new Safeguard())
    ->imagesOnly()
    ->maxDimensions(2048, 2048)  // Max 2048x2048
    ->minDimensions(100, 100)     // Min 100x100
],
```

### PDF Page Limits

```php
'contract' => ['required', (new Safeguard())
    ->pdfsOnly()
    ->maxPages(10)    // Maximum 10 pages
    ->minPages(1)     // Minimum 1 page
],
```

### Block GPS Data

```php
'profile_pic' => ['required', (new Safeguard())
    ->imagesOnly()
    ->blockGps()  // Reject images with GPS location
],
```

### Strip Metadata

```php
'upload' => ['required', (new Safeguard())
    ->imagesOnly()
    ->stripMetadata()  // Automatically remove EXIF data
],
```

### Block JavaScript in PDFs

```php
'invoice' => ['required', (new Safeguard())
    ->pdfsOnly()
    ->blockJavaScript()
    ->blockExternalLinks()
],
```

## Individual Rules

For granular control, use specific validation rules:

### MIME Type Validation

```php
'file' => 'required|safeguard_mime:image/jpeg,image/png'
```

### PHP Code Scanning

```php
'file' => 'required|safeguard_php'
```

### SVG Security

```php
'icon' => 'required|safeguard_svg'
```

### Image Security

```php
'photo' => 'required|safeguard_image'
```

### PDF Security

```php
'document' => 'required|safeguard_pdf'
```

### Image Dimensions

```php
'avatar' => 'required|safeguard_dimensions:100,100,1920,1080'
// Format: min_width,min_height,max_width,max_height
```

### PDF Pages

```php
'contract' => 'required|safeguard_pages:1,10'
// Format: min_pages,max_pages
```

## Combining Rules

You can combine Safeguard rules with Laravel's built-in rules:

```php
$request->validate([
    'avatar' => [
        'required',
        'file',
        'max:2048',  // Laravel's max size (KB)
        (new Safeguard())
            ->imagesOnly()
            ->maxDimensions(1920, 1080)
            ->blockGps()
    ],
]);
```

## Error Messages

Customize error messages:

```php
$request->validate([
    'file' => 'required|safeguard',
], [
    'file.safeguard' => 'The uploaded file failed security checks. Please upload a safe file.',
]);
```

## What's Next?

- [Validation Rules](/guide/validation-rules) - Complete reference of all rules
- [Configuration](/guide/configuration) - Customize security settings
- [Advanced Usage](/guide/advanced) - Complex scenarios
