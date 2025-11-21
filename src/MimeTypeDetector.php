<?php

namespace Abdian\LaravelSafeguard;

use Illuminate\Http\UploadedFile;

/**
 * MimeTypeDetector - Detects real MIME type by analyzing file's magic bytes
 *
 * This class reads the binary signature (magic bytes) at the beginning of a file
 * to determine its actual type, preventing attacks where malicious files are
 * uploaded with fake extensions (e.g., PHP file renamed to .jpg)
 */
class MimeTypeDetector
{
    /**
     * Magic bytes signatures for common file types
     * Each entry maps magic bytes pattern to MIME type
     *
     * @var array<string, string>
     */
    protected array $magicBytes = [
        // Images
        'ffd8ff' => 'image/jpeg',
        '89504e47' => 'image/png',
        '47494638' => 'image/gif',
        '424d' => 'image/bmp',
        '49492a00' => 'image/tiff',
        '4d4d002a' => 'image/tiff',
        '52494646' => 'image/webp', // RIFF header (WebP uses RIFF container)
        '00000100' => 'image/x-icon', // ICO
        '00000200' => 'image/x-icon', // ICO
        '474946383761' => 'image/gif', // GIF87a
        '474946383961' => 'image/gif', // GIF89a

        // Documents
        '25504446' => 'application/pdf',
        '504b0304' => 'application/zip', // Also used by docx, xlsx, etc.
        '504b0506' => 'application/zip', // Empty ZIP
        '504b0708' => 'application/zip', // Spanned ZIP
        'd0cf11e0a1b11ae1' => 'application/msword', // DOC, XLS, PPT (Office 97-2003)
        '0d444f43' => 'application/msword', // Older Word format

        // Text files
        'efbbbf' => 'text/plain', // UTF-8 BOM
        'fffe' => 'text/plain', // UTF-16 LE BOM
        'feff' => 'text/plain', // UTF-16 BE BOM

        // Archives
        '1f8b' => 'application/gzip',
        '1f9d' => 'application/x-compress', // compress
        '1fa0' => 'application/x-lzh', // LZH
        '526172211a07' => 'application/x-rar-compressed', // RAR v5
        '526172211a0700' => 'application/x-rar-compressed', // RAR v1.5+
        '377abcaf271c' => 'application/x-7z-compressed',
        '213c617263683e' => 'application/x-debian-package', // Debian package
        '213c617263683e0a' => 'application/x-archive', // Unix archive
        '425a68' => 'application/x-bzip2', // BZIP2
        'fd377a585a00' => 'application/x-xz', // XZ

        // Media - Video
        '000001ba' => 'video/mpeg',
        '000001b3' => 'video/mpeg',
        '66747970' => 'video/mp4', // Offset 4 bytes
        '1a45dfa3' => 'video/webm',
        '3026b2758e66cf11' => 'video/x-ms-asf', // WMV, WMA, ASF
        '664c7601' => 'video/x-flv', // FLV
        '4f676753' => 'video/ogg', // OGG

        // Media - Audio
        '494433' => 'audio/mpeg', // MP3 with ID3
        'fff3' => 'audio/mpeg', // MP3
        'fffb' => 'audio/mpeg', // MP3
        '664c6143' => 'audio/flac', // FLAC
        '4d546864' => 'audio/midi', // MIDI
        '2321414d52' => 'audio/amr', // AMR

        // Executables (potential threats)
        '4d5a' => 'application/x-msdownload', // Windows executable (PE)
        '7f454c46' => 'application/x-executable', // Linux ELF
        'feedface' => 'application/x-mach-binary', // macOS Mach-O (32-bit)
        'feedfacf' => 'application/x-mach-binary', // macOS Mach-O (64-bit)
        'cafebabe' => 'application/java-archive', // Java class
        '504b0304140008000800' => 'application/java-archive', // JAR
        '23212f' => 'text/x-shellscript', // Shell script (#!)
        '4d5a9000' => 'application/x-dosexec', // DOS executable

        // Scripts (potential threats)
        '3c3f706870' => 'application/x-php', // <?php
        '3c3f3d' => 'application/x-php', // <?=
        '3c25' => 'text/x-jsp', // JSP (<%

        // Web files
        '3c3f786d6c' => 'text/xml', // <?xml
        '3c68746d6c' => 'text/html', // <html
        '3c21444f43545950' => 'text/html', // <!DOCTYPE
        '3c686561643e' => 'text/html', // <head>
        '3c626f64793e' => 'text/html', // <body>

        // Other
        '213c617263683e' => 'application/x-deb', // Debian package
        '4344303031' => 'application/x-iso9660-image', // ISO image
    ];

    /**
     * Detect the real MIME type of a file by analyzing its magic bytes
     *
     * @param UploadedFile|string $file The uploaded file or file path
     * @return string|null The detected MIME type or null if unknown
     */
    public function detect(UploadedFile|string $file): ?string
    {
        $path = $file instanceof UploadedFile ? $file->getRealPath() : $file;

        if (!file_exists($path) || !is_readable($path)) {
            return null;
        }

        // Read first 16 bytes (enough for most signatures)
        $handle = fopen($path, 'rb');
        if ($handle === false) {
            return null;
        }

        $bytes = fread($handle, 16);
        fclose($handle);

        if ($bytes === false) {
            return null;
        }

        // Convert bytes to hex string
        $hex = bin2hex($bytes);

        // Merge custom signatures from config with built-in signatures
        $allSignatures = array_merge(
            config('safeguard.mime_validation.custom_signatures', []),
            $this->magicBytes
        );

        // Check against known signatures (custom signatures checked first)
        foreach ($allSignatures as $signature => $mimeType) {
            if ($this->matchesSignature($hex, $signature)) {
                return $this->refineDetection($hex, $mimeType, $path);
            }
        }

        // Fallback to PHP's built-in detection
        return $this->fallbackDetection($path);
    }

    /**
     * Check if hex string starts with signature
     *
     * @param string $hex The file's hex representation
     * @param string $signature The magic bytes signature to match
     * @return bool True if signature matches
     */
    protected function matchesSignature(string $hex, string $signature): bool
    {
        return str_starts_with($hex, $signature);
    }

    /**
     * Refine detection for file types that need additional checks
     *
     * For example, ZIP-based formats (docx, xlsx, jar) all start with PK signature
     *
     * @param string $hex The file's hex representation
     * @param string $mimeType The initially detected MIME type
     * @param string $path The file path for additional checks
     * @return string The refined MIME type
     */
    protected function refineDetection(string $hex, string $mimeType, string $path): string
    {
        // Refine ZIP-based formats
        if ($mimeType === 'application/zip') {
            return $this->refineZipBasedFormat($path);
        }

        // Refine RIFF container (WebP, AVI, WAV)
        if (str_starts_with($hex, '52494646')) { // RIFF
            return $this->refineRiffFormat($path);
        }

        // Refine ftyp-based formats (MP4, MOV, etc.)
        if ($this->isFtypFormat($path)) {
            return $this->refineFtypFormat($path);
        }

        return $mimeType;
    }

    /**
     * Refine detection for ZIP-based file formats
     *
     * @param string $path The file path
     * @return string The refined MIME type
     */
    protected function refineZipBasedFormat(string $path): string
    {
        $handle = fopen($path, 'rb');
        if ($handle === false) {
            return 'application/zip';
        }

        $content = fread($handle, 512);
        fclose($handle);

        // Check for Office Open XML formats
        if (str_contains($content, 'word/')) {
            return 'application/vnd.openxmlformats-officedocument.wordprocessingml.document';
        }
        if (str_contains($content, 'xl/')) {
            return 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet';
        }
        if (str_contains($content, 'ppt/')) {
            return 'application/vnd.openxmlformats-officedocument.presentationml.presentation';
        }

        return 'application/zip';
    }

    /**
     * Refine detection for RIFF container formats
     *
     * @param string $path The file path
     * @return string The refined MIME type
     */
    protected function refineRiffFormat(string $path): string
    {
        $handle = fopen($path, 'rb');
        if ($handle === false) {
            return 'application/octet-stream';
        }

        // RIFF format: RIFF [size] [format]
        fseek($handle, 8); // Skip to format identifier
        $format = fread($handle, 4);
        fclose($handle);

        return match ($format) {
            'WEBP' => 'image/webp',
            'AVI ' => 'video/x-msvideo',
            'WAVE' => 'audio/wav',
            default => 'application/octet-stream',
        };
    }

    /**
     * Check if file uses ftyp format (ISO base media file format)
     *
     * @param string $path The file path
     * @return bool True if file uses ftyp format
     */
    protected function isFtypFormat(string $path): bool
    {
        $handle = fopen($path, 'rb');
        if ($handle === false) {
            return false;
        }

        fseek($handle, 4);
        $ftyp = fread($handle, 4);
        fclose($handle);

        return $ftyp === 'ftyp';
    }

    /**
     * Refine detection for ftyp-based formats (MP4, MOV, M4A, etc.)
     *
     * @param string $path The file path
     * @return string The refined MIME type
     */
    protected function refineFtypFormat(string $path): string
    {
        $handle = fopen($path, 'rb');
        if ($handle === false) {
            return 'application/octet-stream';
        }

        fseek($handle, 8);
        $brand = fread($handle, 4);
        fclose($handle);

        // Check major brand
        if (in_array($brand, ['isom', 'iso2', 'mp41', 'mp42'])) {
            return 'video/mp4';
        }
        if ($brand === 'qt  ') {
            return 'video/quicktime';
        }
        if (in_array($brand, ['M4A ', 'M4B '])) {
            return 'audio/mp4';
        }

        return 'video/mp4'; // Default to MP4
    }

    /**
     * Fallback detection using PHP's fileinfo extension
     *
     * @param string $path The file path
     * @return string|null The detected MIME type or null
     */
    protected function fallbackDetection(string $path): ?string
    {
        if (!function_exists('mime_content_type')) {
            return null;
        }

        $mimeType = mime_content_type($path);
        return $mimeType !== false ? $mimeType : null;
    }

    /**
     * Check if detected MIME type is potentially dangerous
     *
     * @param string $mimeType The MIME type to check
     * @return bool True if MIME type is dangerous
     */
    public function isDangerous(string $mimeType): bool
    {
        $dangerousTypes = config('safeguard.mime_validation.dangerous_types', [
            'application/x-msdownload',
            'application/x-executable',
            'application/x-php',
            'text/x-php',
            'application/x-httpd-php',
            'text/x-shellscript',
            'application/x-sh',
        ]);

        return in_array($mimeType, $dangerousTypes);
    }
}
