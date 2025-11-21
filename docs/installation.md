# Installation Guide

Complete installation instructions for Laravel Safeguard.

---

## Requirements

Before installing, ensure your system meets these requirements:

- **PHP:** 8.1 or higher
- **Laravel:** 10.x or 11.x
- **PHP Extensions:**
  - `fileinfo` (enabled by default)
  - `gd` or `imagick` (for image manipulation)

---

## Installation

### Step 1: Install via Composer

```bash
composer require abdian/laravel-safeguard
```

### Step 2: Publish Configuration (Optional)

```bash
php artisan vendor:publish --tag=safeguard-config
```

This creates `config/safeguard.php` for customization.

### Step 3: Verify Installation

```bash
php artisan list | grep safeguard
```

---

## Configuration

### Basic Setup

No configuration required! The package works out of the box with secure defaults.

### Custom Configuration

Edit `config/safeguard.php` to customize behavior:

```php
return [
    'mime_validation' => [
        'strict_check' => true,
        'block_dangerous' => true,
    ],

    'php_scanning' => [
        'enabled' => true,
        'mode' => 'default',
    ],

    'logging' => [
        'enabled' => true,
        'channel' => 'stack',
    ],
];
```

### Environment Variables

Add to your `.env` file:

```env
SAFEGUARD_MIME_STRICT=true
SAFEGUARD_PHP_SCAN=true
SAFEGUARD_SVG_SCAN=true
SAFEGUARD_IMAGE_SCAN=true
SAFEGUARD_PDF_SCAN=true
SAFEGUARD_LOGGING=true
```

---

## Upgrade Guide

### From 1.x to 2.x

```bash
composer update abdian/laravel-safeguard
php artisan vendor:publish --tag=safeguard-config --force
```

Check `CHANGELOG.md` for breaking changes.

---

## Troubleshooting

### fileinfo Extension Not Found

**Error:** `Call to undefined function finfo_open()`

**Solution:**

**Ubuntu/Debian:**
```bash
sudo apt-get install php-fileinfo
sudo systemctl restart apache2
```

**macOS:**
```bash
brew install php
```

**Windows:**

Uncomment in `php.ini`:
```ini
extension=fileinfo
```

### GD/Imagick Not Found

For image metadata stripping, install:

```bash
# Ubuntu/Debian
sudo apt-get install php-gd php-imagick

# macOS
brew install gd imagemagick
```

### Permission Issues

Ensure Laravel can read uploaded files:

```bash
chmod -R 755 storage/
chown -R www-data:www-data storage/
```

---

## Uninstallation

```bash
composer remove abdian/laravel-safeguard
rm config/safeguard.php
```

---

## Next Steps

- [Quick Start Guide](quick-start.md)
- [Validation Rules](validation-rules.md)
- [Configuration](configuration.md)
