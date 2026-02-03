<?php

namespace Abdian\LaravelSafeguard\Rules;

use Closure;
use Illuminate\Contracts\Validation\ValidationRule;
use Illuminate\Http\UploadedFile;

/**
 * Safeguard - Comprehensive security validation for uploaded files
 *
 * This validation rule runs ALL security checks on uploaded files:
 * - Real MIME type detection (magic bytes)
 * - PHP code scanning
 * - SVG security scanning
 * - Image security scanning (EXIF/GPS)
 * - PDF security scanning
 * - Dimensions validation (for images)
 * - Page count validation (for PDFs)
 * - Strict extension-MIME matching (prevents extension spoofing)
 *
 * Usage:
 *   'file' => ['required', new Safeguard()]
 *
 * Or via string rule:
 *   'file' => 'required|safeguard'
 *
 * Integration with Laravel's mimes rule (RECOMMENDED):
 *   'file' => 'required|safeguard|mimes:jpg,png,pdf'
 *
 *   When used with Laravel's 'mimes' rule, safeguard automatically:
 *   - Converts extensions to MIME types
 *   - Enables strict extension-MIME matching
 *   - Prevents extension spoofing attacks
 *
 * Fluent configuration:
 *   'file' => ['required', (new Safeguard())
 *       ->allowedMimes(['image/jpeg', 'image/png', 'application/pdf'])
 *       ->strictExtensionMatching(true)  // Prevent extension spoofing
 *       ->maxDimensions(1920, 1080)
 *       ->maxPages(10)
 *       ->blockGps()
 *       ->stripMetadata()
 *   ]
 */
class Safeguard implements ValidationRule
{
    /**
     * Allowed MIME types (null = allow all safe types)
     *
     * @var array<string>|null
     */
    protected ?array $allowedMimes = null;

    /**
     * Maximum image width
     *
     * @var int|null
     */
    protected ?int $maxWidth = null;

    /**
     * Maximum image height
     *
     * @var int|null
     */
    protected ?int $maxHeight = null;

    /**
     * Minimum image width
     *
     * @var int|null
     */
    protected ?int $minWidth = null;

    /**
     * Minimum image height
     *
     * @var int|null
     */
    protected ?int $minHeight = null;

    /**
     * Maximum PDF pages
     *
     * @var int|null
     */
    protected ?int $maxPages = null;

    /**
     * Minimum PDF pages
     *
     * @var int|null
     */
    protected ?int $minPages = null;

    /**
     * Whether to block images with GPS data
     *
     * @var bool
     */
    protected bool $blockGps = false;

    /**
     * Whether to strip metadata from images
     *
     * @var bool
     */
    protected bool $stripMetadata = false;

    /**
     * Whether to block PDFs with JavaScript
     *
     * @var bool
     */
    protected bool $blockJavaScript = false;

    /**
     * Whether to block PDFs with external links
     *
     * @var bool
     */
    protected bool $blockExternalLinks = false;

    /**
     * Whether to scan archive contents
     *
     * @var bool
     */
    protected bool $scanArchives = false;

    /**
     * Whether to block Office macros
     *
     * @var bool
     */
    protected bool $blockMacros = false;

    /**
     * Whether to enforce strict extension-MIME matching
     *
     * When enabled, the file's extension must strictly match its detected MIME type.
     * This prevents extension spoofing attacks (e.g., a JPEG file named "image.png").
     *
     * @var bool
     */
    protected bool $strictExtensionMatch = false;

    /**
     * Run the validation rule
     *
     * @param string $attribute The attribute name being validated
     * @param mixed $value The value to validate (should be UploadedFile)
     * @param Closure $fail Callback to call if validation fails
     * @return void
     */
    public function validate(string $attribute, mixed $value, Closure $fail): void
    {
        // Check if value is an uploaded file
        if (!$value instanceof UploadedFile) {
            $fail("The {$attribute} must be a valid uploaded file.");
            return;
        }

        // Check if file was uploaded successfully
        if (!$value->isValid()) {
            $fail("The {$attribute} upload failed.");
            return;
        }

        // Detect file type once for all validations
        $detector = new \Abdian\LaravelSafeguard\MimeTypeDetector();
        $detectedMime = $detector->detect($value);

        // 1. MIME Type Validation (only if specific types are required)
        if ($this->allowedMimes !== null && !empty($this->allowedMimes)) {
            $mimeRule = new SafeguardMime($this->allowedMimes);
            $mimeRule->validate($attribute, $value, function ($message) use ($fail) {
                $fail($message);
            });
        } else {
            // No specific MIME types required, but still block dangerous types
            if ($detectedMime !== null && $detector->isDangerous($detectedMime)) {
                $fail("The {$attribute} file type is not allowed for security reasons.");
                return;
            }
        }

        // 1.5. Strict Extension-MIME Matching (when enabled)
        if ($this->strictExtensionMatch && $detectedMime !== null) {
            $extension = strtolower($value->getClientOriginalExtension());
            if (!empty($extension)) {
                $extensionMap = new \Abdian\LaravelSafeguard\ExtensionMimeMap();

                if (!$extensionMap::isValidExtensionForMime($extension, $detectedMime)) {
                    // Get expected extensions for this MIME type
                    $expectedExtensions = $extensionMap::getExtensions($detectedMime);
                    $expectedStr = !empty($expectedExtensions) ? implode(', ', $expectedExtensions) : 'unknown';

                    $fail("The {$attribute} file extension (.{$extension}) does not match its content type ({$detectedMime}). Expected extension: {$expectedStr}");
                    return;
                }
            }
        }

        // 2. PHP Code Scanning
        $phpRule = new SafeguardPhp();
        $phpRule->validate($attribute, $value, function ($message) use ($fail) {
            $fail($message);
        });

        // 3. SVG Security Scanning (if SVG)
        if ($detectedMime === 'image/svg+xml' || $value->getClientOriginalExtension() === 'svg') {
            $svgRule = new SafeguardSvg();
            $svgRule->validate($attribute, $value, function ($message) use ($fail) {
                $fail($message);
            });
        }

        // 4. Image Security Scanning (if image)
        if (str_starts_with($detectedMime ?? '', 'image/') && $detectedMime !== 'image/svg+xml') {
            $imageRule = new SafeguardImage();

            if ($this->blockGps) {
                $imageRule->blockGps();
            }

            if ($this->stripMetadata) {
                $imageRule->stripMetadata();
            }

            $imageRule->validate($attribute, $value, function ($message) use ($fail) {
                $fail($message);
            });

            // Image dimensions validation
            if ($this->maxWidth !== null || $this->maxHeight !== null ||
                $this->minWidth !== null || $this->minHeight !== null) {
                $dimensionsRule = new SafeguardDimensions(
                    $this->maxWidth,
                    $this->maxHeight,
                    $this->minWidth,
                    $this->minHeight
                );

                $dimensionsRule->validate($attribute, $value, function ($message) use ($fail) {
                    $fail($message);
                });
            }
        }

        // 5. PDF Security Scanning (if PDF)
        if ($detectedMime === 'application/pdf' || $value->getClientOriginalExtension() === 'pdf') {
            $pdfRule = new SafeguardPdf();

            if ($this->blockJavaScript) {
                $pdfRule->blockJavaScript();
            }

            if ($this->blockExternalLinks) {
                $pdfRule->blockExternalLinks();
            }

            $pdfRule->validate($attribute, $value, function ($message) use ($fail) {
                $fail($message);
            });

            // PDF pages validation
            if ($this->minPages !== null || $this->maxPages !== null) {
                $pagesRule = new SafeguardPages($this->minPages, $this->maxPages);

                $pagesRule->validate($attribute, $value, function ($message) use ($fail) {
                    $fail($message);
                });
            }
        }

        // 6. Archive Content Scanning (if archive and enabled)
        if ($this->scanArchives) {
            $archiveScanner = new \Abdian\LaravelSafeguard\ArchiveScanner();
            if ($archiveScanner->isArchive($value)) {
                $archiveRule = new SafeguardArchive();
                $archiveRule->validate($attribute, $value, function ($message) use ($fail) {
                    $fail($message);
                });
            }
        }

        // 7. Office Document Macro Scanning (if Office document and enabled)
        if ($this->blockMacros) {
            $officeScanner = new \Abdian\LaravelSafeguard\OfficeScanner();
            if ($officeScanner->isOfficeDocument($value->getRealPath())) {
                $officeRule = new SafeguardOffice();
                $officeRule->validate($attribute, $value, function ($message) use ($fail) {
                    $fail($message);
                });
            }
        }
    }

    /**
     * Set allowed MIME types
     *
     * @param array<string> $mimes Allowed MIME types
     * @return self
     */
    public function allowedMimes(array $mimes): self
    {
        $this->allowedMimes = $mimes;
        return $this;
    }

    /**
     * Set maximum image dimensions
     *
     * @param int $width Maximum width
     * @param int $height Maximum height
     * @return self
     */
    public function maxDimensions(int $width, int $height): self
    {
        $this->maxWidth = $width;
        $this->maxHeight = $height;
        return $this;
    }

    /**
     * Set minimum image dimensions
     *
     * @param int $width Minimum width
     * @param int $height Minimum height
     * @return self
     */
    public function minDimensions(int $width, int $height): self
    {
        $this->minWidth = $width;
        $this->minHeight = $height;
        return $this;
    }

    /**
     * Set image dimensions (both min and max)
     *
     * @param int $minWidth Minimum width
     * @param int $minHeight Minimum height
     * @param int $maxWidth Maximum width
     * @param int $maxHeight Maximum height
     * @return self
     */
    public function dimensions(int $minWidth, int $minHeight, int $maxWidth, int $maxHeight): self
    {
        $this->minWidth = $minWidth;
        $this->minHeight = $minHeight;
        $this->maxWidth = $maxWidth;
        $this->maxHeight = $maxHeight;
        return $this;
    }

    /**
     * Set maximum PDF pages
     *
     * @param int $pages Maximum pages
     * @return self
     */
    public function maxPages(int $pages): self
    {
        $this->maxPages = $pages;
        return $this;
    }

    /**
     * Set minimum PDF pages
     *
     * @param int $pages Minimum pages
     * @return self
     */
    public function minPages(int $pages): self
    {
        $this->minPages = $pages;
        return $this;
    }

    /**
     * Set PDF page range
     *
     * @param int $min Minimum pages
     * @param int $max Maximum pages
     * @return self
     */
    public function pages(int $min, int $max): self
    {
        $this->minPages = $min;
        $this->maxPages = $max;
        return $this;
    }

    /**
     * Block images that contain GPS location data
     *
     * @return self
     */
    public function blockGps(): self
    {
        $this->blockGps = true;
        return $this;
    }

    /**
     * Automatically strip metadata from images
     *
     * @return self
     */
    public function stripMetadata(): self
    {
        $this->stripMetadata = true;
        return $this;
    }

    /**
     * Block PDFs that contain JavaScript
     *
     * @return self
     */
    public function blockJavaScript(): self
    {
        $this->blockJavaScript = true;
        return $this;
    }

    /**
     * Block PDFs that contain external links
     *
     * @return self
     */
    public function blockExternalLinks(): self
    {
        $this->blockExternalLinks = true;
        return $this;
    }

    /**
     * Enable or disable strict extension-MIME matching
     *
     * When enabled, the file's extension must strictly match its detected MIME type.
     * This prevents extension spoofing attacks where a file has a misleading extension.
     *
     * Example: A JPEG file named "image.png" will be rejected because the .png
     * extension doesn't match the image/jpeg MIME type.
     *
     * @param bool $enable Whether to enable strict matching (default: true)
     * @return self
     */
    public function strictExtensionMatching(bool $enable = true): self
    {
        $this->strictExtensionMatch = $enable;
        return $this;
    }

    /**
     * Images only - allow only image MIME types
     *
     * @return self
     */
    public function imagesOnly(): self
    {
        $this->allowedMimes = ['image/*'];
        return $this;
    }

    /**
     * PDFs only - allow only PDF MIME type
     *
     * @return self
     */
    public function pdfsOnly(): self
    {
        $this->allowedMimes = ['application/pdf'];
        return $this;
    }

    /**
     * Documents only - allow common document formats
     *
     * @return self
     */
    public function documentsOnly(): self
    {
        $this->allowedMimes = [
            'application/pdf',
            'application/msword',
            'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
            'application/vnd.ms-excel',
            'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
        ];
        return $this;
    }

    /**
     * Enable archive content scanning
     *
     * When enabled, archive files (ZIP, TAR, etc.) will be scanned for:
     * - Dangerous file extensions
     * - Path traversal attacks
     * - Zip bombs
     *
     * @return self
     */
    public function scanArchives(): self
    {
        $this->scanArchives = true;
        return $this;
    }

    /**
     * Block Office documents containing macros
     *
     * When enabled, Office documents (DOCX, XLSX, PPTX) will be scanned for:
     * - VBA macros
     * - ActiveX controls
     * - Macro-enabled documents disguised as regular documents
     *
     * @return self
     */
    public function blockMacros(): self
    {
        $this->blockMacros = true;
        return $this;
    }

    /**
     * Archives only - allow only archive MIME types
     *
     * @return self
     */
    public function archivesOnly(): self
    {
        $this->allowedMimes = [
            'application/zip',
            'application/x-tar',
            'application/gzip',
            'application/x-gzip',
            'application/x-rar-compressed',
            'application/x-7z-compressed',
        ];
        $this->scanArchives = true;
        return $this;
    }
}
