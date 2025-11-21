# Logging & Monitoring Guide

Complete guide to security event logging and monitoring.

---

## Overview

Laravel Safeguard automatically logs all security threats, helping you monitor and respond to malicious upload attempts.

---

## Quick Setup

### Enable Logging

```env
SAFEGUARD_LOGGING=true
SAFEGUARD_LOG_CHANNEL=stack
SAFEGUARD_LOG_DETAILED=true
```

That's it! All security events will be logged.

---

## Custom Security Log Channel

Create a dedicated security log channel for better organization.

### 1. Configure Channel

Add to `config/logging.php`:

```php
'channels' => [
    'security' => [
        'driver' => 'daily',
        'path' => storage_path('logs/security.log'),
        'level' => 'warning',
        'days' => 90,  // Keep logs for 3 months
    ],
],
```

### 2. Use Channel

```env
SAFEGUARD_LOG_CHANNEL=security
```

### 3. Verify

```bash
tail -f storage/logs/security.log
```

---

## Log Output Format

### Basic Log Entry

```
[2025-01-21 18:45:23] security.ERROR: Malicious content detected in PDF file
```

### Detailed Log Entry

```json
{
  "event_type": "pdf_threat",
  "threat_level": "high",
  "file": {
    "name": "contract.pdf",
    "size": "240 KB",
    "hash": "a3b2c1d4e5f6789..."
  },
  "threats": [
    "JavaScript code detected in PDF",
    "Dangerous PDF action detected: Launch"
  ],
  "user_id": 123,
  "ip": "192.168.1.100"
}
```

---

## Event Types

Laravel Safeguard logs these event types:

| Event Type | Threat Level | Description |
|------------|--------------|-------------|
| `mime_mismatch` | medium | Real MIME doesn't match extension |
| `dangerous_file` | critical | Executable or script detected |
| `php_code` | high | PHP code found in file |
| `svg_xss` | high | XSS vulnerability in SVG |
| `image_threat` | high | Malicious code in image metadata |
| `pdf_threat` | high | Malicious content in PDF |
| `gps_detected` | low | GPS data found in image |
| `dimension_exceeded` | low | Image dimensions exceeded |
| `page_exceeded` | low | PDF pages exceeded |

---

## Threat Levels

### Critical
- Executables (.exe, .sh, .bat)
- Scripts (.php, .js with dangerous content)

**Log Level:** `critical`

### High
- PHP code in uploads
- XSS in SVG files
- Malicious PDF content
- Image metadata exploits

**Log Level:** `error`

### Medium
- MIME type mismatches
- JavaScript in PDFs (when allowed)

**Log Level:** `warning`

### Low
- GPS data detection
- Dimension/page limits

**Log Level:** `info`

---

## Configuration

### Basic Configuration

```php
// config/safeguard.php
'logging' => [
    'enabled' => true,
    'channel' => 'stack',
    'detailed' => true,
    'hash_algorithm' => 'sha256',
],
```

### Options

```php
'logging' => [
    // Enable/disable logging
    'enabled' => env('SAFEGUARD_LOGGING', true),

    // Log channel (from config/logging.php)
    'channel' => env('SAFEGUARD_LOG_CHANNEL', 'stack'),

    // Include full threat details
    'detailed' => env('SAFEGUARD_LOG_DETAILED', true),

    // File hash algorithm: 'md5', 'sha256', or false
    'hash_algorithm' => 'sha256',
],
```

---

## Log Information

### What's Logged

**Always:**
- Event type
- Threat level
- Timestamp
- Message

**If `detailed` is true:**
- File information (name, size, hash)
- Threat details
- User ID (if authenticated)
- IP address
- Additional context

---

## Monitoring Examples

### Monitor Security Logs

```bash
# Watch security logs in real-time
tail -f storage/logs/security.log

# Search for high-threat events
grep "ERROR" storage/logs/security.log

# Count threats by type
grep "event_type" storage/logs/security.log | sort | uniq -c
```

### Laravel Log Viewer

Use packages like [rap2hpoutre/laravel-log-viewer](https://github.com/rap2hpoutre/laravel-log-viewer):

```bash
composer require rap2hpoutre/laravel-log-viewer
```

Access at: `http://yourapp.test/logs`

---

## Alerting

### Email Alerts

Create a custom log channel with email notifications:

```php
// config/logging.php
'channels' => [
    'security-email' => [
        'driver' => 'monolog',
        'handler' => \Monolog\Handler\NativeMailerHandler::class,
        'handler_with' => [
            'to' => 'security@example.com',
            'subject' => 'Security Alert',
            'from' => 'noreply@example.com',
            'level' => 'error',
        ],
    ],

    'security' => [
        'driver' => 'stack',
        'channels' => ['daily', 'security-email'],
    ],
],
```

### Slack Notifications

```php
'channels' => [
    'security-slack' => [
        'driver' => 'slack',
        'url' => env('LOG_SLACK_WEBHOOK_URL'),
        'username' => 'Security Bot',
        'emoji' => ':warning:',
        'level' => 'error',
    ],

    'security' => [
        'driver' => 'stack',
        'channels' => ['daily', 'security-slack'],
    ],
],
```

---

## Forensic Analysis

### File Hashing

Enable file hashing for forensic analysis:

```php
'logging' => [
    'hash_algorithm' => 'sha256',
],
```

Log output includes:
```json
{
  "file": {
    "name": "malicious.pdf",
    "hash": "a3b2c1d4e5f6789..."
  }
}
```

Use hash to:
- Track file across systems
- Report to security databases
- Check against known malware

### Log Retention

Keep security logs for compliance:

```php
// config/logging.php
'channels' => [
    'security' => [
        'driver' => 'daily',
        'days' => 90,  // 3 months
        // or
        'days' => 365,  // 1 year for compliance
    ],
],
```

---

## Performance Impact

### Logging Overhead

Logging has minimal impact:
- **File hash calculation:** ~10ms for 5MB file
- **Log write:** ~1-5ms
- **Total:** < 15ms per upload

### Optimization

Disable logging in development:

```env
# .env.local
SAFEGUARD_LOGGING=false
```

Or use async logging:

```php
// config/logging.php
'channels' => [
    'security' => [
        'driver' => 'daily',
        'tap' => [App\Logging\AsyncLogger::class],
    ],
],
```

---

## Compliance & Audit

### GDPR Considerations

Log carefully to comply with GDPR:

```php
'logging' => [
    // Don't log file contents
    'detailed' => false,

    // Hash instead of storing filename
    'hash_algorithm' => 'sha256',
],
```

### Audit Trail

Security logs provide audit trail for:
- Who uploaded what
- When threats were detected
- What actions were taken
- Source IP addresses

---

## Troubleshooting

### Logs Not Appearing

**Check permissions:**
```bash
chmod -R 755 storage/logs/
chown -R www-data:www-data storage/logs/
```

**Check configuration:**
```bash
php artisan config:clear
php artisan config:cache
```

**Verify channel exists:**
```bash
php artisan tinker
>>> config('logging.channels.security')
```

### Too Many Logs

Adjust log level:

```php
'channels' => [
    'security' => [
        'level' => 'error',  // Only errors and above
    ],
],
```

Or disable low-priority events:

```env
SAFEGUARD_LOG_DETAILED=false
```

---

## Best Practices

1. **Use Dedicated Channel** — Separate security logs from application logs
2. **Long Retention** — Keep security logs for 90+ days
3. **Monitor Regularly** — Check logs weekly for patterns
4. **Set Up Alerts** — Email/Slack for critical threats
5. **Hash Files** — Enable for forensic analysis
6. **Rotate Logs** — Use daily driver with retention policy
7. **Secure Logs** — Restrict access to security team only

---

## Next Steps

- [Configuration Guide](configuration.md) — Configure logging behavior
- [Advanced Usage](advanced.md) — Complex monitoring scenarios
- [Examples](examples.md) — Real-world monitoring setups
