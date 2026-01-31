# Validation Rules

Complete reference for all validation rules.

## String Rules

### safeguard

All-in-one security validation.

```php
'file' => 'required|safeguard'
```

Performs all security checks.

### safeguard_mime

Validates real MIME type via magic bytes.

```php
'file' => 'required|safeguard_mime:image/jpeg,image/png'
```

### safeguard_php

Scans for malicious PHP code.

```php
'file' => 'required|safeguard_php'
```

### safeguard_image

Analyzes image EXIF metadata.

```php
'photo' => 'required|safeguard_image'
```

### safeguard_pdf

Scans PDF for JavaScript.

```php
'document' => 'required|safeguard_pdf'
```

### safeguard_dimensions

Validates image dimensions.

```php
'image' => 'required|safeguard_dimensions:100,100,1920,1080'
```

Format: `min_width,min_height,max_width,max_height`

### safeguard_pages

Validates PDF page count.

```php
'pdf' => 'required|safeguard_pages:1,10'
```

Format: `min_pages,max_pages`

## Fluent API

### imagesOnly()

```php
(new Safeguard())->imagesOnly()
```

### pdfsOnly()

```php
(new Safeguard())->pdfsOnly()
```

### documentsOnly()

```php
(new Safeguard())->documentsOnly()
```

### allowedMimes(array $mimes)

```php
(new Safeguard())->allowedMimes(['image/jpeg', 'application/pdf'])
```

### maxDimensions(int $width, int $height)

```php
(new Safeguard())->maxDimensions(1920, 1080)
```

### minDimensions(int $width, int $height)

```php
(new Safeguard())->minDimensions(100, 100)
```

### blockGps()

```php
(new Safeguard())->blockGps()
```

### stripMetadata()

```php
(new Safeguard())->stripMetadata()
```

### maxPages(int $pages)

```php
(new Safeguard())->maxPages(10)
```

### minPages(int $pages)

```php
(new Safeguard())->minPages(1)
```

### blockJavaScript()

```php
(new Safeguard())->blockJavaScript()
```

### strictMode()

```php
(new Safeguard())->strictMode()
```

## Next Steps

- [Configuration](/guide/config) - Customize defaults
- [API Reference](/api/) - Complete API docs
