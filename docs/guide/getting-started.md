# Getting Started

## Installation

Install Laravel Safeguard via Composer:

```bash
composer require abdian/laravel-safeguard
```

The package will auto-register via Laravel's package discovery.

## Basic Usage

The simplest way to use Laravel Safeguard is with the `safeguard` validation rule:

```php
use Illuminate\Http\Request;

public function upload(Request $request)
{
    $request->validate([
        'file' => 'required|safeguard',
    ]);

    // File is safe to process
    $file = $request->file('file');
    $path = $file->store('uploads');

    return response()->json(['path' => $path]);
}
```

This single rule performs:
- ✅ Real MIME type detection via magic bytes
- ✅ PHP code scanning for malicious functions
- ✅ XSS vulnerability detection in SVG files
- ✅ Image metadata analysis for hidden threats
- ✅ PDF security scanning for JavaScript
- ✅ Automatic blocking of dangerous file types

## Configuration

Publish the configuration file (optional):

```bash
php artisan vendor:publish --tag=safeguard-config
```

This creates `config/safeguard.php` where you can customize all security settings.

## What's Next?

- [Basic Usage](/guide/basic-usage) - Learn different ways to use Safeguard
- [Validation Rules](/guide/validation-rules) - All available validation rules
- [Configuration](/guide/configuration) - Customize security settings
- [Advanced Usage](/guide/advanced) - Complex scenarios and tips
