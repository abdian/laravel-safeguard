# Configuration

Customize Laravel Safeguard settings.

## Publish Config

```bash
php artisan vendor:publish --tag=safeguard-config
```

This creates `config/safeguard.php`.

## General Settings

```php
'default_security_level' => 'strict', // or 'standard'
'max_file_size' => 10240, // KB
```

## Image Settings

```php
'images' => [
    'max_width' => 4096,
    'max_height' => 4096,
    'block_gps' => false,
    'strip_metadata' => false,
],
```

## PDF Settings

```php
'pdf' => [
    'max_pages' => 100,
    'block_javascript' => true,
],
```

## PHP Scanning

```php
'php_scanning' => [
    'enabled' => true,
    'strict_mode' => true,
    'dangerous_functions' => [
        'eval', 'exec', 'system', 'shell_exec',
        // ...
    ],
],
```

## Allowed MIME Types

```php
'allowed_mime_types' => [
    'image/jpeg',
    'image/png',
    'application/pdf',
],
```

## Blocked Extensions

```php
'blocked_extensions' => [
    'exe', 'bat', 'cmd', 'sh',
],
```

## Logging

```php
'logging' => [
    'enabled' => true,
    'channel' => 'stack',
],
```

## Environment Variables

```env
SAFEGUARD_ENABLED=true
SAFEGUARD_MAX_FILE_SIZE=10240
SAFEGUARD_BLOCK_GPS=false
```

## Next Steps

- [Validation Rules](/guide/rules) - Use the rules
- [API Reference](/api/) - Complete reference
