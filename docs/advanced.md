# Advanced Usage Guide

Complex scenarios and advanced techniques for Laravel Safeguard.

---

## Form Request Validation

Create reusable Form Requests with Safeguard rules.

### Basic Form Request

```php
php artisan make:request UploadAvatarRequest
```

```php
<?php

namespace App\Http\Requests;

use Illuminate\Foundation\Http\FormRequest;
use Abdian\LaravelSafeguard\Rules\Safeguard;

class UploadAvatarRequest extends FormRequest
{
    public function authorize(): bool
    {
        return true;
    }

    public function rules(): array
    {
        return [
            'avatar' => ['required', 'image', 'max:5120', (new Safeguard())
                ->imagesOnly()
                ->maxDimensions(1920, 1080)
                ->minDimensions(200, 200)
                ->blockGps()
                ->stripMetadata()
            ],
        ];
    }

    public function messages(): array
    {
        return [
            'avatar.required' => 'Please upload your profile photo.',
            'avatar.image' => 'The file must be an image.',
            'avatar.max' => 'Image size must not exceed 5MB.',
        ];
    }
}
```

### Use in Controller

```php
public function upload(UploadAvatarRequest $request)
{
    // Already validated
    $path = $request->file('avatar')->store('avatars', 'public');

    auth()->user()->update(['avatar' => $path]);

    return back()->with('success', 'Avatar updated!');
}
```

---

## Multiple File Uploads

Handle multiple file uploads with security.

### Array Validation

```php
$request->validate([
    'photos' => 'required|array|min:1|max:10',
    'photos.*' => ['required', 'image', (new Safeguard())
        ->imagesOnly()
        ->maxDimensions(3000, 3000)
    ],
]);

foreach ($request->file('photos') as $photo) {
    $photo->store('gallery');
}
```

### Different Rules Per Index

```php
$request->validate([
    'files' => 'required|array',
    'files.0' => 'required|safeguard_mime:image/*',  // First must be image
    'files.1' => 'required|safeguard_mime:application/pdf',  // Second must be PDF
]);
```

---

## Conditional Validation

Apply rules conditionally based on context.

### Based on User Role

```php
use Abdian\LaravelSafeguard\Rules\Safeguard;

$rules = [
    'file' => ['required', new Safeguard()],
];

// Admins can upload larger files
if (auth()->user()->isAdmin()) {
    $rules['file'][] = 'max:20480';  // 20MB
} else {
    $rules['file'][] = 'max:5120';   // 5MB
}

$request->validate($rules);
```

### Based on File Type

```php
$request->validate([
    'file' => 'required|file',
]);

$file = $request->file('file');
$mime = $file->getMimeType();

if (str_starts_with($mime, 'image/')) {
    $request->validate([
        'file' => [(new Safeguard())->imagesOnly()->maxDimensions(1920, 1080)],
    ]);
} elseif ($mime === 'application/pdf') {
    $request->validate([
        'file' => [(new Safeguard())->pdfsOnly()->maxPages(50)],
    ]);
}
```

---

## Custom Error Messages

### Per-Field Messages

```php
$request->validate([
    'avatar' => 'required|safeguard',
    'document' => 'required|safeguard_pdf',
], [
    'avatar.safeguard' => 'Your profile photo contains threats. Please upload a different image.',
    'document.safeguard_pdf' => 'PDF document failed security checks.',
]);
```

### Global Messages

```php
// lang/en/validation.php
'custom' => [
    'avatar' => [
        'safeguard' => 'Profile photo security check failed.',
    ],
    'document' => [
        'safeguard_pdf' => 'Document contains malicious content.',
    ],
],
```

---

## Performance Optimization

### Disable Unused Scanners

```env
# Don't use SVGs? Disable scanner
SAFEGUARD_SVG_SCAN=false

# Don't use PDFs? Disable scanner
SAFEGUARD_PDF_SCAN=false
```

### Async Validation

For large files, validate asynchronously:

```php
use Illuminate\Support\Facades\Queue;

Queue::push(function () use ($file) {
    $validator = validator(
        ['file' => $file],
        ['file' => 'required|safeguard']
    );

    if ($validator->fails()) {
        // Handle failure
        Mail::to($user)->send(new ValidationFailed());
    } else {
        // Process file
        $file->store('uploads');
    }
});
```

### Cache Results

Cache validation results for identical files:

```php
use Illuminate\Support\Facades\Cache;

$hash = hash_file('sha256', $file->getRealPath());

$isValid = Cache::remember("safeguard:{$hash}", 3600, function () use ($file) {
    $validator = validator(
        ['file' => $file],
        ['file' => 'required|safeguard']
    );

    return !$validator->fails();
});
```

---

## Testing

### Unit Tests

```php
use Abdian\LaravelSafeguard\Rules\Safeguard;
use Illuminate\Http\UploadedFile;

test('blocks malicious pdf', function () {
    $file = UploadedFile::fake()->create('malicious.pdf', 100);

    $validator = validator(
        ['file' => $file],
        ['file' => ['required', new Safeguard()]]
    );

    expect($validator->fails())->toBeTrue();
});

test('allows safe image', function () {
    $file = UploadedFile::fake()->image('avatar.jpg');

    $validator = validator(
        ['file' => $file],
        ['file' => ['required', new Safeguard()]]
    );

    expect($validator->passes())->toBeTrue();
});
```

### Feature Tests

```php
test('user can upload safe avatar', function () {
    $file = UploadedFile::fake()->image('avatar.jpg');

    $response = $this->post('/upload', [
        'avatar' => $file,
    ]);

    $response->assertStatus(200);
    $this->assertDatabaseHas('users', [
        'avatar' => 'avatars/' . $file->hashName(),
    ]);
});

test('user cannot upload php file as image', function () {
    $file = UploadedFile::fake()->createWithContent(
        'malicious.jpg',
        '<?php system($_GET["cmd"]); ?>'
    );

    $response = $this->post('/upload', [
        'avatar' => $file,
    ]);

    $response->assertStatus(422);
    $response->assertJsonValidationErrors('avatar');
});
```

---

## API Validation

### RESTful API

```php
use Abdian\LaravelSafeguard\Rules\Safeguard;

class FileUploadController extends Controller
{
    public function upload(Request $request)
    {
        $validator = Validator::make($request->all(), [
            'file' => ['required', new Safeguard()],
        ]);

        if ($validator->fails()) {
            return response()->json([
                'success' => false,
                'errors' => $validator->errors(),
            ], 422);
        }

        $path = $request->file('file')->store('uploads');

        return response()->json([
            'success' => true,
            'path' => $path,
        ]);
    }
}
```

### GraphQL

```php
use Nuwave\Lighthouse\Schema\TypeRegistry;
use Abdian\LaravelSafeguard\Rules\Safeguard;

class FileUploadMutation
{
    public function upload($root, array $args)
    {
        validator($args, [
            'file' => ['required', new Safeguard()],
        ])->validate();

        return $args['file']->store('uploads');
    }
}
```

---

## Multi-Tenant Applications

Different rules per tenant:

```php
use Abdian\LaravelSafeguard\Rules\Safeguard;

class UploadController extends Controller
{
    public function upload(Request $request)
    {
        $tenant = auth()->user()->tenant;

        $safeguard = (new Safeguard())
            ->maxDimensions($tenant->max_width, $tenant->max_height)
            ->maxPages($tenant->max_pdf_pages);

        if ($tenant->strip_metadata) {
            $safeguard->stripMetadata();
        }

        if ($tenant->block_gps) {
            $safeguard->blockGps();
        }

        $request->validate([
            'file' => ['required', $safeguard],
        ]);

        // Process upload
    }
}
```

---

## Queue Processing

Validate files in queue jobs:

```php
use Illuminate\Bus\Queueable;
use Abdian\LaravelSafeguard\Rules\Safeguard;

class ProcessUpload implements ShouldQueue
{
    use Queueable;

    public function __construct(public string $filePath)
    {
    }

    public function handle()
    {
        $file = new \Illuminate\Http\UploadedFile(
            $this->filePath,
            basename($this->filePath)
        );

        $validator = validator(
            ['file' => $file],
            ['file' => ['required', new Safeguard()]]
        );

        if ($validator->fails()) {
            // Handle failure
            Log::error('Queued file validation failed', [
                'file' => $this->filePath,
                'errors' => $validator->errors(),
            ]);

            return;
        }

        // Process file
    }
}
```

---

## FAQ

### Q: Does it work with S3/Cloud storage?

**A:** Yes, but validate before uploading to cloud:

```php
$request->validate([
    'file' => 'required|safeguard',
]);

// Now upload to S3
$path = $request->file('file')->store('uploads', 's3');
```

### Q: Can I validate files already on disk?

**A:** Yes:

```php
$file = new \Illuminate\Http\UploadedFile(
    '/path/to/file.pdf',
    'file.pdf'
);

$validator = validator(
    ['file' => $file],
    ['file' => 'required|safeguard']
);
```

### Q: Does it slow down uploads?

**A:** Minimal impact (~10-50ms depending on file size and checks).

### Q: Can I disable specific scanners?

**A:** Yes, via config or .env:

```env
SAFEGUARD_PDF_SCAN=false
SAFEGUARD_SVG_SCAN=false
```

### Q: Works with Livewire?

**A:** Yes:

```php
use Livewire\WithFileUploads;
use Abdian\LaravelSafeguard\Rules\Safeguard;

class UploadComponent extends Component
{
    use WithFileUploads;

    public $file;

    public function save()
    {
        $this->validate([
            'file' => ['required', new Safeguard()],
        ]);
    }
}
```

### Q: Can I customize error messages?

**A:** Yes, multiple ways. See [Custom Error Messages](#custom-error-messages) above.

---

## Troubleshooting

### Issue: "fileinfo extension not found"

**Solution:**

```bash
# Ubuntu/Debian
sudo apt-get install php-fileinfo

# macOS
brew install php

# Enable in php.ini
extension=fileinfo
```

### Issue: GD/Imagick errors

**Solution:**

```bash
# Ubuntu/Debian
sudo apt-get install php-gd php-imagick

# macOS
brew install gd imagemagick
```

### Issue: Memory limit errors

**Solution:**

```ini
; php.ini
memory_limit = 256M
upload_max_filesize = 20M
post_max_size = 20M
```

---

## Next Steps

- [Examples](examples.md) — Real-world implementation examples
- [Configuration](configuration.md) — Detailed configuration guide
- [Customization](customization.md) — Extend functionality
