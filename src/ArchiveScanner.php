<?php

namespace Abdian\LaravelSafeguard;

use Abdian\LaravelSafeguard\Concerns\ValidatesFileAccess;
use Illuminate\Http\UploadedFile;
use ZipArchive;
use PharData;

/**
 * ArchiveScanner - Scans archive files for malicious content
 *
 * Detects security threats in archive files (ZIP, TAR, GZIP):
 * - Dangerous file extensions (PHP, EXE, etc.)
 * - Path traversal attacks (../)
 * - Zip bombs (high compression ratio)
 * - Excessive file counts
 * - Nested archives beyond depth limit
 */
class ArchiveScanner
{
    use ValidatesFileAccess;

    /**
     * Default blocked extensions
     *
     * @var array<string>
     */
    protected array $blockedExtensions = [
        'php', 'phtml', 'php3', 'php4', 'php5', 'php7', 'phps', 'phar',
        'exe', 'com', 'bat', 'cmd', 'ps1', 'vbs', 'vbe', 'js', 'jse',
        'wsf', 'wsh', 'msc', 'scr', 'pif', 'hta', 'cpl',
        'sh', 'bash', 'zsh', 'csh', 'ksh',
        'jar', 'war', 'ear',
        'dll', 'so', 'dylib',
        'asp', 'aspx', 'jsp', 'jspx', 'cfm',
    ];

    /**
     * Archive extensions that trigger nested scanning
     *
     * @var array<string>
     */
    protected array $archiveExtensions = [
        'zip', 'tar', 'gz', 'tgz', 'tar.gz', 'bz2', 'tbz2', 'tar.bz2',
        '7z', 'rar', 'cab', 'iso',
    ];

    /**
     * Maximum compression ratio (default: 100:1)
     *
     * @var int
     */
    protected int $maxCompressionRatio = 100;

    /**
     * Maximum uncompressed size in bytes (default: 500MB)
     *
     * @var int
     */
    protected int $maxUncompressedSize = 524288000;

    /**
     * Maximum number of files in archive (default: 10000)
     *
     * @var int
     */
    protected int $maxFilesCount = 10000;

    /**
     * Maximum nesting depth for nested archives (default: 3)
     *
     * @var int
     */
    protected int $maxNestingDepth = 3;

    /**
     * Scan an archive file for security threats
     *
     * @param UploadedFile|string $file The archive file to scan
     * @param int $currentDepth Current nesting depth (for recursive calls)
     * @return array{safe: bool, threats: array<string>, files_count: int, uncompressed_size: int} Scan result
     */
    public function scan(UploadedFile|string $file, int $currentDepth = 0): array
    {
        $path = $file instanceof UploadedFile ? $file->getRealPath() : $file;

        if (!file_exists($path) || !is_readable($path)) {
            return $this->failResult(['File cannot be read']);
        }

        // Validate file access (symlink check, path validation)
        if (!$this->validateFileAccess($path)) {
            $reason = $this->getFileAccessFailureReason($path);
            return $this->failResult([$reason]);
        }

        // Load configuration
        $this->loadConfiguration();

        // Check nesting depth
        if ($currentDepth >= $this->maxNestingDepth) {
            return $this->failResult(['Archive nesting depth exceeds limit']);
        }

        // Detect archive type and scan
        $archiveType = $this->detectArchiveType($path);

        return match ($archiveType) {
            'zip' => $this->scanZipArchive($path, $currentDepth),
            'tar', 'tar.gz', 'tar.bz2' => $this->scanTarArchive($path, $currentDepth),
            'rar' => $this->scanRarArchive($path, $currentDepth),
            default => $this->failResult(['Unsupported archive format']),
        };
    }

    /**
     * Scan a ZIP archive
     *
     * @param string $path Path to ZIP file
     * @param int $currentDepth Current nesting depth
     * @return array{safe: bool, threats: array<string>, files_count: int, uncompressed_size: int}
     */
    protected function scanZipArchive(string $path, int $currentDepth): array
    {
        $zip = new ZipArchive();
        $result = $zip->open($path, ZipArchive::RDONLY);

        if ($result !== true) {
            return $this->failResult(['Failed to open ZIP archive']);
        }

        $threats = [];
        $totalUncompressedSize = 0;
        $filesCount = $zip->numFiles;
        $compressedSize = filesize($path);

        // Check file count limit
        if ($filesCount > $this->maxFilesCount) {
            $zip->close();
            return $this->failResult(["Archive contains too many files ({$filesCount} > {$this->maxFilesCount})"]);
        }

        // Scan each file in the archive
        for ($i = 0; $i < $filesCount; $i++) {
            $stat = $zip->statIndex($i);
            if ($stat === false) {
                continue;
            }

            $fileName = $stat['name'];
            $uncompressedSize = $stat['size'];
            $totalUncompressedSize += $uncompressedSize;

            // Early exit if uncompressed size exceeds limit
            if ($totalUncompressedSize > $this->maxUncompressedSize) {
                $zip->close();
                return $this->failResult(['Archive uncompressed size exceeds limit']);
            }

            // Check for path traversal
            $traversalThreats = $this->checkPathTraversal($fileName);
            $threats = array_merge($threats, $traversalThreats);

            // Check for dangerous extensions
            $extensionThreats = $this->checkDangerousExtension($fileName);
            $threats = array_merge($threats, $extensionThreats);

            // Check for nested archives
            if ($this->isArchiveExtension($fileName) && $currentDepth < $this->maxNestingDepth - 1) {
                $threats[] = "Nested archive detected: {$fileName}";
            }
        }

        // Check compression ratio (zip bomb detection)
        if ($compressedSize > 0) {
            $ratio = $totalUncompressedSize / $compressedSize;
            if ($ratio > $this->maxCompressionRatio) {
                $threats[] = "Potential zip bomb detected: compression ratio " . round($ratio, 1) . ":1";
            }
        }

        $zip->close();

        return [
            'safe' => empty($threats),
            'threats' => array_unique($threats),
            'files_count' => $filesCount,
            'uncompressed_size' => $totalUncompressedSize,
        ];
    }

    /**
     * Scan a TAR/GZIP archive
     *
     * @param string $path Path to TAR file
     * @param int $currentDepth Current nesting depth
     * @return array{safe: bool, threats: array<string>, files_count: int, uncompressed_size: int}
     */
    protected function scanTarArchive(string $path, int $currentDepth): array
    {
        try {
            $phar = new PharData($path);
        } catch (\Exception $e) {
            return $this->failResult(['Failed to open TAR archive: ' . $e->getMessage()]);
        }

        $threats = [];
        $totalUncompressedSize = 0;
        $filesCount = 0;
        $compressedSize = filesize($path);

        try {
            $iterator = new \RecursiveIteratorIterator($phar);

            foreach ($iterator as $file) {
                $filesCount++;

                // Check file count limit
                if ($filesCount > $this->maxFilesCount) {
                    return $this->failResult(["Archive contains too many files ({$filesCount} > {$this->maxFilesCount})"]);
                }

                $fileName = $file->getPathname();
                $uncompressedSize = $file->getSize();
                $totalUncompressedSize += $uncompressedSize;

                // Early exit if uncompressed size exceeds limit
                if ($totalUncompressedSize > $this->maxUncompressedSize) {
                    return $this->failResult(['Archive uncompressed size exceeds limit']);
                }

                // Extract relative path from phar path
                $relativePath = preg_replace('/^phar:\/\/.*\.(?:tar|tar\.gz|tgz|tar\.bz2|tbz2)\//i', '', $fileName);

                // Check for path traversal
                $traversalThreats = $this->checkPathTraversal($relativePath);
                $threats = array_merge($threats, $traversalThreats);

                // Check for dangerous extensions
                $extensionThreats = $this->checkDangerousExtension($relativePath);
                $threats = array_merge($threats, $extensionThreats);
            }
        } catch (\Exception $e) {
            return $this->failResult(['Error scanning TAR archive: ' . $e->getMessage()]);
        }

        // Check compression ratio
        if ($compressedSize > 0) {
            $ratio = $totalUncompressedSize / $compressedSize;
            if ($ratio > $this->maxCompressionRatio) {
                $threats[] = "Potential zip bomb detected: compression ratio " . round($ratio, 1) . ":1";
            }
        }

        return [
            'safe' => empty($threats),
            'threats' => array_unique($threats),
            'files_count' => $filesCount,
            'uncompressed_size' => $totalUncompressedSize,
        ];
    }

    /**
     * Scan a RAR archive (requires rar extension)
     *
     * @param string $path Path to RAR file
     * @param int $currentDepth Current nesting depth
     * @return array{safe: bool, threats: array<string>, files_count: int, uncompressed_size: int}
     */
    protected function scanRarArchive(string $path, int $currentDepth): array
    {
        // Check if RAR extension is available
        if (!class_exists('RarArchive')) {
            // Fail closed by default (configurable)
            $failOpen = $this->getArchiveConfig('rar_fail_open', false);
            if ($failOpen) {
                return [
                    'safe' => true,
                    'threats' => ['RAR scanning skipped: rar extension not available'],
                    'files_count' => 0,
                    'uncompressed_size' => 0,
                ];
            }
            return $this->failResult(['RAR scanning requires rar extension']);
        }

        $rar = \RarArchive::open($path);
        if ($rar === false) {
            return $this->failResult(['Failed to open RAR archive']);
        }

        $threats = [];
        $totalUncompressedSize = 0;
        $filesCount = 0;
        $compressedSize = filesize($path);

        $entries = $rar->getEntries();
        if ($entries === false) {
            $rar->close();
            return $this->failResult(['Failed to read RAR entries']);
        }

        foreach ($entries as $entry) {
            $filesCount++;

            if ($filesCount > $this->maxFilesCount) {
                $rar->close();
                return $this->failResult(["Archive contains too many files ({$filesCount} > {$this->maxFilesCount})"]);
            }

            $fileName = $entry->getName();
            $uncompressedSize = $entry->getUnpackedSize();
            $totalUncompressedSize += $uncompressedSize;

            if ($totalUncompressedSize > $this->maxUncompressedSize) {
                $rar->close();
                return $this->failResult(['Archive uncompressed size exceeds limit']);
            }

            $traversalThreats = $this->checkPathTraversal($fileName);
            $threats = array_merge($threats, $traversalThreats);

            $extensionThreats = $this->checkDangerousExtension($fileName);
            $threats = array_merge($threats, $extensionThreats);
        }

        $rar->close();

        if ($compressedSize > 0) {
            $ratio = $totalUncompressedSize / $compressedSize;
            if ($ratio > $this->maxCompressionRatio) {
                $threats[] = "Potential zip bomb detected: compression ratio " . round($ratio, 1) . ":1";
            }
        }

        return [
            'safe' => empty($threats),
            'threats' => array_unique($threats),
            'files_count' => $filesCount,
            'uncompressed_size' => $totalUncompressedSize,
        ];
    }

    /**
     * Check for path traversal attacks
     *
     * @param string $fileName File name from archive
     * @return array<string> Threats found
     */
    protected function checkPathTraversal(string $fileName): array
    {
        $threats = [];

        // Check for ../ patterns (Unix)
        if (preg_match('/\.\.[\\/]/', $fileName)) {
            $threats[] = "Path traversal detected: {$fileName}";
        }

        // Check for absolute paths
        if (preg_match('/^[\/\\\\]/', $fileName) || preg_match('/^[A-Za-z]:/', $fileName)) {
            $threats[] = "Absolute path detected in archive: {$fileName}";
        }

        // Check for URL-encoded traversal
        if (preg_match('/%2e%2e[%2f%5c]/i', $fileName)) {
            $threats[] = "URL-encoded path traversal detected: {$fileName}";
        }

        // Check for null bytes
        if (str_contains($fileName, "\0")) {
            $threats[] = "Null byte in filename detected: {$fileName}";
        }

        return $threats;
    }

    /**
     * Check for dangerous file extensions
     *
     * @param string $fileName File name from archive
     * @return array<string> Threats found
     */
    protected function checkDangerousExtension(string $fileName): array
    {
        $threats = [];

        // Get extension (handle multiple extensions like .tar.gz)
        $extension = strtolower(pathinfo($fileName, PATHINFO_EXTENSION));

        // Also check for double extensions like file.php.jpg
        $baseName = strtolower(pathinfo($fileName, PATHINFO_FILENAME));
        $secondExtension = pathinfo($baseName, PATHINFO_EXTENSION);

        if (in_array($extension, $this->blockedExtensions, true)) {
            $threats[] = "Dangerous file detected in archive: {$fileName}";
        }

        // Check for hidden dangerous extension (e.g., malware.php.jpg)
        if (!empty($secondExtension) && in_array($secondExtension, $this->blockedExtensions, true)) {
            $threats[] = "Hidden dangerous extension detected: {$fileName}";
        }

        return $threats;
    }

    /**
     * Check if filename has an archive extension
     *
     * @param string $fileName File name to check
     * @return bool
     */
    protected function isArchiveExtension(string $fileName): bool
    {
        $extension = strtolower(pathinfo($fileName, PATHINFO_EXTENSION));
        return in_array($extension, $this->archiveExtensions, true);
    }

    /**
     * Detect archive type from file content
     *
     * @param string $path Path to file
     * @return string|null Archive type or null
     */
    protected function detectArchiveType(string $path): ?string
    {
        $handle = fopen($path, 'rb');
        if ($handle === false) {
            return null;
        }

        $header = fread($handle, 262);
        fclose($handle);

        if ($header === false || strlen($header) < 4) {
            return null;
        }

        // ZIP: PK\x03\x04
        if (str_starts_with($header, "PK\x03\x04")) {
            return 'zip';
        }

        // GZIP: \x1f\x8b
        if (str_starts_with($header, "\x1f\x8b")) {
            return 'tar.gz';
        }

        // BZIP2: BZ
        if (str_starts_with($header, "BZ")) {
            return 'tar.bz2';
        }

        // RAR: Rar!\x1a\x07
        if (str_starts_with($header, "Rar!\x1a\x07")) {
            return 'rar';
        }

        // TAR: Check for ustar at position 257
        if (strlen($header) >= 262 && substr($header, 257, 5) === 'ustar') {
            return 'tar';
        }

        // 7Z: 7z\xbc\xaf\x27\x1c
        if (str_starts_with($header, "7z\xbc\xaf\x27\x1c")) {
            return '7z';
        }

        return null;
    }

    /**
     * Load configuration from Laravel config
     *
     * @return void
     */
    protected function loadConfiguration(): void
    {
        $this->maxCompressionRatio = $this->getArchiveConfig('max_compression_ratio', 100);
        $this->maxUncompressedSize = $this->getArchiveConfig('max_uncompressed_size', 500 * 1024 * 1024);
        $this->maxFilesCount = $this->getArchiveConfig('max_files_count', 10000);
        $this->maxNestingDepth = $this->getArchiveConfig('max_nesting_depth', 3);

        $customBlocked = $this->getArchiveConfig('blocked_extensions', []);
        if (!empty($customBlocked)) {
            $this->blockedExtensions = array_unique(array_merge($this->blockedExtensions, $customBlocked));
        }

        $excludeExtensions = $this->getArchiveConfig('exclude_extensions', []);
        if (!empty($excludeExtensions)) {
            $this->blockedExtensions = array_diff($this->blockedExtensions, $excludeExtensions);
        }
    }

    /**
     * Get archive configuration value
     *
     * @param string $key Configuration key
     * @param mixed $default Default value
     * @return mixed
     */
    protected function getArchiveConfig(string $key, mixed $default = null): mixed
    {
        if (function_exists('config') && function_exists('app')) {
            try {
                return config("safeguard.archive_scanning.{$key}", $default) ?? $default;
            } catch (\Throwable) {
                return $default;
            }
        }
        return $default;
    }

    /**
     * Create a failure result array
     *
     * @param array<string> $threats Threat messages
     * @return array{safe: bool, threats: array<string>, files_count: int, uncompressed_size: int}
     */
    protected function failResult(array $threats): array
    {
        return [
            'safe' => false,
            'threats' => $threats,
            'files_count' => 0,
            'uncompressed_size' => 0,
        ];
    }

    /**
     * Set maximum compression ratio
     *
     * @param int $ratio Maximum ratio (e.g., 100 for 100:1)
     * @return self
     */
    public function setMaxCompressionRatio(int $ratio): self
    {
        $this->maxCompressionRatio = $ratio;
        return $this;
    }

    /**
     * Set maximum uncompressed size
     *
     * @param int $bytes Maximum size in bytes
     * @return self
     */
    public function setMaxUncompressedSize(int $bytes): self
    {
        $this->maxUncompressedSize = $bytes;
        return $this;
    }

    /**
     * Set maximum files count
     *
     * @param int $count Maximum number of files
     * @return self
     */
    public function setMaxFilesCount(int $count): self
    {
        $this->maxFilesCount = $count;
        return $this;
    }

    /**
     * Set maximum nesting depth
     *
     * @param int $depth Maximum depth
     * @return self
     */
    public function setMaxNestingDepth(int $depth): self
    {
        $this->maxNestingDepth = $depth;
        return $this;
    }

    /**
     * Set blocked extensions
     *
     * @param array<string> $extensions Extensions to block
     * @return self
     */
    public function setBlockedExtensions(array $extensions): self
    {
        $this->blockedExtensions = $extensions;
        return $this;
    }

    /**
     * Add blocked extensions
     *
     * @param array<string> $extensions Extensions to add
     * @return self
     */
    public function addBlockedExtensions(array $extensions): self
    {
        $this->blockedExtensions = array_unique(array_merge($this->blockedExtensions, $extensions));
        return $this;
    }

    /**
     * Check if a file is an archive
     *
     * @param UploadedFile|string $file The file to check
     * @return bool
     */
    public function isArchive(UploadedFile|string $file): bool
    {
        $path = $file instanceof UploadedFile ? $file->getRealPath() : $file;

        if (!file_exists($path)) {
            return false;
        }

        return $this->detectArchiveType($path) !== null;
    }
}
