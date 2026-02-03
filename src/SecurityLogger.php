<?php

namespace Abdian\LaravelSafeguard;

use Illuminate\Http\UploadedFile;
use Illuminate\Support\Facades\Log;

/**
 * SecurityLogger - Centralized logging system for security events
 *
 * Logs all security-related events with detailed context information
 * including user, request, file details, and threat information.
 */
class SecurityLogger
{
    /**
     * Threat level constants
     */
    const LEVEL_LOW = 'low';
    const LEVEL_MEDIUM = 'medium';
    const LEVEL_HIGH = 'high';
    const LEVEL_CRITICAL = 'critical';

    /**
     * Event type constants
     */
    const EVENT_MIME_MISMATCH = 'mime_mismatch';
    const EVENT_DANGEROUS_FILE = 'dangerous_file';
    const EVENT_PHP_CODE = 'php_code';
    const EVENT_SVG_XSS = 'svg_xss';
    const EVENT_IMAGE_THREAT = 'image_threat';
    const EVENT_PDF_THREAT = 'pdf_threat';
    const EVENT_GPS_DETECTED = 'gps_detected';
    const EVENT_DIMENSION_EXCEEDED = 'dimension_exceeded';
    const EVENT_PAGE_EXCEEDED = 'page_exceeded';
    const EVENT_XXE_DETECTED = 'xxe_detected';
    const EVENT_ARCHIVE_THREAT = 'archive_threat';
    const EVENT_MACRO_DETECTED = 'macro_detected';
    const EVENT_SYMLINK_DETECTED = 'symlink_detected';
    const EVENT_ZIPBOMB_DETECTED = 'zipbomb_detected';

    /**
     * Log a security threat
     *
     * @param string $eventType Event type constant
     * @param string $level Threat level (low, medium, high, critical)
     * @param string $message Human-readable message
     * @param array<string, mixed> $context Additional context
     * @return void
     */
    public static function logThreat(string $eventType, string $level, string $message, array $context = []): void
    {
        // Check if logging is enabled
        if (!config('safeguard.logging.enabled', true)) {
            return;
        }

        // Build log context
        $logContext = [
            'event_type' => $eventType,
            'threat_level' => $level,
        ];

        // Add detailed information if enabled
        if (config('safeguard.logging.detailed', true)) {
            $logContext = array_merge($logContext, $context);
        }

        // Add user information if authenticated
        if (auth()->check()) {
            $logContext['user_id'] = auth()->id();
        }

        // Add request information
        if (request()) {
            $logContext['ip'] = request()->ip();
        }

        // Get log channel
        $channel = config('safeguard.logging.channel', 'stack');

        // Map threat level to Laravel log level
        $laravelLogLevel = match ($level) {
            self::LEVEL_CRITICAL => 'critical',
            self::LEVEL_HIGH => 'error',
            self::LEVEL_MEDIUM => 'warning',
            self::LEVEL_LOW => 'info',
            default => 'warning',
        };

        // Write log
        Log::channel($channel)->log($laravelLogLevel, $message, $logContext);
    }

    /**
     * Log file information with threat context
     *
     * @param UploadedFile $file The uploaded file
     * @param string $eventType Event type
     * @param string $level Threat level
     * @param string $message Message
     * @param array<string, mixed> $additionalContext Additional context
     * @return void
     */
    public static function logFileEvent(
        UploadedFile $file,
        string $eventType,
        string $level,
        string $message,
        array $additionalContext = []
    ): void {
        $context = $additionalContext;

        // Add file information
        $context['file'] = [
            'name' => $file->getClientOriginalName(),
            'size' => self::formatBytes($file->getSize()),
        ];

        // Calculate file hash if enabled
        $hashAlgorithm = config('safeguard.logging.hash_algorithm', 'sha256');
        if ($hashAlgorithm && in_array($hashAlgorithm, ['md5', 'sha256'])) {
            $context['file']['hash'] = hash_file($hashAlgorithm, $file->getRealPath());
        }

        self::logThreat($eventType, $level, $message, $context);
    }

    /**
     * Format bytes to human-readable format
     *
     * @param int $bytes Bytes
     * @return string
     */
    protected static function formatBytes(int $bytes): string
    {
        $units = ['B', 'KB', 'MB', 'GB', 'TB'];

        for ($i = 0; $bytes > 1024 && $i < count($units) - 1; $i++) {
            $bytes /= 1024;
        }

        return round($bytes, 2) . ' ' . $units[$i];
    }
}
