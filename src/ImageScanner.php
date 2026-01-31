<?php

namespace Abdian\LaravelSafeguard;

use Abdian\LaravelSafeguard\Concerns\ValidatesFileAccess;
use Illuminate\Http\UploadedFile;

/**
 * ImageScanner - Scans images for hidden malicious content and metadata threats
 *
 * Images can contain hidden PHP code in EXIF data, trailing bytes, or comments.
 * This scanner detects these security threats and can strip sensitive metadata.
 *
 * Security features:
 * - Symlink validation (TOCTOU protection)
 * - PHP code detection in binary content
 * - EXIF metadata scanning
 */
class ImageScanner
{
    use ValidatesFileAccess;
    /**
     * Suspicious EXIF tags that might contain code
     *
     * @var array<string>
     */
    protected array $suspiciousExifTags = [
        'Comment',
        'UserComment',
        'ImageDescription',
        'Artist',
        'Copyright',
        'Software',
        'ProcessingSoftware',
        'DocumentName',
        'HostComputer',
        'XPComment',
        'XPAuthor',
        'XPTitle',
        'XPSubject',
    ];

    /**
     * Sensitive GPS tags to check
     *
     * @var array<string>
     */
    protected array $gpsExifTags = [
        'GPSLatitude',
        'GPSLongitude',
        'GPSAltitude',
        'GPSLatitudeRef',
        'GPSLongitudeRef',
        'GPSAltitudeRef',
        'GPSTimeStamp',
        'GPSDateStamp',
    ];

    /**
     * Scan an image file for security threats
     *
     * @param UploadedFile|string $file The image file to scan
     * @param bool $checkGps Whether to check for GPS data
     * @return array{safe: bool, threats: array<string>, has_gps: bool, metadata: array<string>} Scan result
     */
    public function scan(UploadedFile|string $file, bool $checkGps = true): array
    {
        $path = $file instanceof UploadedFile ? $file->getRealPath() : $file;

        if (!file_exists($path) || !is_readable($path)) {
            return ['safe' => false, 'threats' => ['File cannot be read'], 'has_gps' => false, 'metadata' => []];
        }

        // Validate file access (symlink check, path validation)
        if (!$this->validateFileAccess($path)) {
            $reason = $this->getFileAccessFailureReason($path);
            return ['safe' => false, 'threats' => [$reason], 'has_gps' => false, 'metadata' => []];
        }

        $threats = [];
        $hasGps = false;
        $metadata = [];

        // Check if EXIF extension is available
        if (!function_exists('exif_read_data')) {
            $threats[] = 'EXIF extension not available for scanning';
            return ['safe' => false, 'threats' => $threats, 'has_gps' => false, 'metadata' => []];
        }

        // Read file content for binary analysis
        $content = file_get_contents($path);
        if ($content === false) {
            return ['safe' => false, 'threats' => ['Failed to read file content'], 'has_gps' => false, 'metadata' => []];
        }

        // Scan for PHP code in binary content
        $phpThreats = $this->scanForPhpCode($content);
        if (!empty($phpThreats)) {
            $threats = array_merge($threats, $phpThreats);
        }

        // Scan for suspicious patterns in trailing bytes
        $trailingThreats = $this->scanTrailingBytes($content, $path);
        if (!empty($trailingThreats)) {
            $threats = array_merge($threats, $trailingThreats);
        }

        // Scan EXIF metadata
        try {
            $exifData = @exif_read_data($path, null, true);

            if ($exifData !== false) {
                // Check for suspicious EXIF content
                $exifThreats = $this->scanExifData($exifData);
                if (!empty($exifThreats)) {
                    $threats = array_merge($threats, $exifThreats);
                }

                // Check for GPS data
                if ($checkGps) {
                    $hasGps = $this->hasGpsData($exifData);
                }

                // Extract metadata summary
                $metadata = $this->extractMetadataSummary($exifData);
            }
        } catch (\Exception $e) {
            // EXIF reading failed, not necessarily a threat
        }

        return [
            'safe' => empty($threats),
            'threats' => array_unique($threats),
            'has_gps' => $hasGps,
            'metadata' => $metadata,
        ];
    }

    /**
     * Scan for PHP code in image binary content
     *
     * @param string $content Image binary content
     * @return array<string> Found threats
     */
    protected function scanForPhpCode(string $content): array
    {
        $threats = [];

        // Check for PHP opening tags
        if (preg_match('/<\?php/i', $content)) {
            $threats[] = 'PHP opening tag (<?php) found in image data';
        }

        if (preg_match('/<\?=/i', $content)) {
            $threats[] = 'PHP short echo tag (<?=) found in image data';
        }

        // Check for common PHP functions
        $dangerousFunctions = ['eval', 'exec', 'system', 'shell_exec', 'base64_decode'];
        foreach ($dangerousFunctions as $func) {
            if (preg_match('/\b' . preg_quote($func, '/') . '\s*\(/i', $content)) {
                $threats[] = "Suspicious PHP function ({$func}) found in image data";
            }
        }

        return $threats;
    }

    /**
     * Scan trailing bytes after image end marker
     *
     * @param string $content Image binary content
     * @param string $path File path for format detection
     * @return array<string> Found threats
     */
    protected function scanTrailingBytes(string $content, string $path): array
    {
        $threats = [];

        // Detect image format and find end marker
        $imageInfo = @getimagesize($path);
        if ($imageInfo === false) {
            return $threats;
        }

        $mimeType = $imageInfo['mime'] ?? '';
        $endMarker = null;

        // Find appropriate end marker based on image type
        switch ($mimeType) {
            case 'image/jpeg':
                $endMarker = "\xFF\xD9"; // JPEG EOI marker
                break;
            case 'image/png':
                $endMarker = "\x49\x45\x4E\x44\xAE\x42\x60\x82"; // PNG IEND chunk
                break;
            case 'image/gif':
                $endMarker = "\x3B"; // GIF trailer
                break;
        }

        if ($endMarker !== null) {
            $endPos = strrpos($content, $endMarker);
            if ($endPos !== false) {
                $trailingBytes = substr($content, $endPos + strlen($endMarker));

                // Check if there are significant trailing bytes
                if (strlen($trailingBytes) > 100) {
                    $threats[] = 'Suspicious trailing data found after image end marker';

                    // Check if trailing bytes contain PHP code
                    if (preg_match('/<\?php|eval|exec|system/i', $trailingBytes)) {
                        $threats[] = 'PHP code detected in trailing bytes';
                    }
                }
            }
        }

        return $threats;
    }

    /**
     * Scan EXIF metadata for malicious content
     *
     * @param array<mixed> $exifData EXIF data array
     * @return array<string> Found threats
     */
    protected function scanExifData(array $exifData): array
    {
        $threats = [];

        foreach ($exifData as $section => $data) {
            if (!is_array($data)) {
                continue;
            }

            foreach ($data as $tag => $value) {
                if (!is_string($value)) {
                    continue;
                }

                // Check if this is a suspicious tag
                if (in_array($tag, $this->suspiciousExifTags)) {
                    // Check for PHP code
                    if (preg_match('/<\?php|<\?=|eval\s*\(|exec\s*\(/i', $value)) {
                        $threats[] = "Suspicious PHP code found in EXIF tag: {$tag}";
                    }

                    // Check for shell commands
                    if (preg_match('/bash|sh\s+-c|cmd\.exe/i', $value)) {
                        $threats[] = "Suspicious shell command found in EXIF tag: {$tag}";
                    }

                    // Check for URLs (potential XSS)
                    if (preg_match('/javascript:|data:text\/html/i', $value)) {
                        $threats[] = "Suspicious URL protocol found in EXIF tag: {$tag}";
                    }
                }
            }
        }

        return $threats;
    }

    /**
     * Check if EXIF data contains GPS information
     *
     * @param array<mixed> $exifData EXIF data array
     * @return bool True if GPS data found
     */
    protected function hasGpsData(array $exifData): bool
    {
        if (!isset($exifData['GPS']) || !is_array($exifData['GPS'])) {
            return false;
        }

        foreach ($this->gpsExifTags as $tag) {
            if (isset($exifData['GPS'][$tag])) {
                return true;
            }
        }

        return false;
    }

    /**
     * Extract metadata summary for logging
     *
     * @param array<mixed> $exifData EXIF data array
     * @return array<string> Metadata summary
     */
    protected function extractMetadataSummary(array $exifData): array
    {
        $summary = [];

        $interestingTags = [
            'Make', 'Model', 'Software', 'DateTime',
            'Artist', 'Copyright', 'ImageDescription'
        ];

        foreach ($exifData as $section => $data) {
            if (!is_array($data)) {
                continue;
            }

            foreach ($interestingTags as $tag) {
                if (isset($data[$tag]) && is_string($data[$tag])) {
                    $summary[$tag] = $data[$tag];
                }
            }
        }

        return $summary;
    }

    /**
     * Strip EXIF metadata from image (create cleaned copy)
     *
     * @param UploadedFile|string $file Source image file
     * @param string $outputPath Output path for cleaned image
     * @return bool True on success
     */
    public function stripMetadata(UploadedFile|string $file, string $outputPath): bool
    {
        $sourcePath = $file instanceof UploadedFile ? $file->getRealPath() : $file;

        if (!file_exists($sourcePath) || !is_readable($sourcePath)) {
            return false;
        }

        // Get image info
        $imageInfo = @getimagesize($sourcePath);
        if ($imageInfo === false) {
            return false;
        }

        $mimeType = $imageInfo['mime'] ?? '';

        // Load image based on type
        $image = null;
        switch ($mimeType) {
            case 'image/jpeg':
                $image = @imagecreatefromjpeg($sourcePath);
                break;
            case 'image/png':
                $image = @imagecreatefrompng($sourcePath);
                break;
            case 'image/gif':
                $image = @imagecreatefromgif($sourcePath);
                break;
        }

        if ($image === false) {
            return false;
        }

        // Save without metadata
        $result = false;
        switch ($mimeType) {
            case 'image/jpeg':
                $result = @imagejpeg($image, $outputPath, 90);
                break;
            case 'image/png':
                $result = @imagepng($image, $outputPath);
                break;
            case 'image/gif':
                $result = @imagegif($image, $outputPath);
                break;
        }

        imagedestroy($image);
        return $result;
    }

    /**
     * Check if file is an image
     *
     * @param UploadedFile|string $file The file to check
     * @return bool True if image
     */
    public function isImage(UploadedFile|string $file): bool
    {
        $path = $file instanceof UploadedFile ? $file->getRealPath() : $file;

        if (!file_exists($path)) {
            return false;
        }

        $imageInfo = @getimagesize($path);
        return $imageInfo !== false;
    }
}
