<?php

namespace Abdian\LaravelSafeguard\Rules;

use Abdian\LaravelSafeguard\PdfScanner;
use Abdian\LaravelSafeguard\SecurityLogger;
use Closure;
use Illuminate\Contracts\Validation\ValidationRule;
use Illuminate\Http\UploadedFile;

/**
 * SafeguardPdf - Validates that PDF files don't contain malicious content
 *
 * This validation rule scans PDF files for:
 * - JavaScript code
 * - Dangerous actions (/Launch, /JavaScript, /URI)
 * - Malicious URLs
 * - Embedded executable files
 * - Obfuscated content
 *
 * Usage:
 *   'document' => ['required', new SafeguardPdf()]
 *
 * Or via string rule:
 *   'document' => 'required|safeguard_pdf'
 */
class SafeguardPdf implements ValidationRule
{
    /**
     * PDF scanner instance
     *
     * @var PdfScanner
     */
    protected PdfScanner $scanner;

    /**
     * Whether to include threat details in error message
     *
     * @var bool
     */
    protected bool $showThreats;

    /**
     * Whether to block PDFs with JavaScript
     *
     * @var bool
     */
    protected bool $blockJavaScript;

    /**
     * Whether to block PDFs with external links
     *
     * @var bool
     */
    protected bool $blockExternalLinks;

    /**
     * Create a new rule instance
     *
     * @param bool $showThreats Whether to show threat details in error message
     */
    public function __construct(bool $showThreats = false)
    {
        $this->scanner = new PdfScanner();
        $this->showThreats = $showThreats;
        $this->blockJavaScript = false;
        $this->blockExternalLinks = false;
    }

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

        // Check if PDF scanning is enabled
        if (!config('safeguard.pdf_scanning.enabled', true)) {
            return; // Skip scanning if disabled
        }

        // Check if file is actually a PDF
        if (!$this->scanner->isPdf($value)) {
            $fail("The {$attribute} is not a valid PDF file.");
            return;
        }

        // Scan the PDF for malicious content
        $result = $this->scanner->scan($value);

        // Check for security threats
        if (!$result['safe']) {
            // Extract metadata for logging
            $metadata = $this->scanner->extractMetadata($value);

            // Log the security incident using SecurityLogger
            SecurityLogger::logFileEvent(
                $value,
                SecurityLogger::EVENT_PDF_THREAT,
                SecurityLogger::LEVEL_HIGH,
                'Malicious content detected in PDF file',
                [
                    'attribute' => $attribute,
                    'threats' => $result['threats'],
                    'has_javascript' => $result['has_javascript'],
                    'has_external_links' => $result['has_external_links'],
                    'metadata' => $metadata,
                ]
            );

            // Build error message
            if ($this->showThreats && !empty($result['threats'])) {
                $threatList = implode(', ', array_slice($result['threats'], 0, 3));
                $fail("The {$attribute} contains malicious content: {$threatList}");
            } else {
                $fail("The {$attribute} contains potentially malicious content and cannot be uploaded.");
            }
            return;
        }

        // Check for JavaScript if blocking is enabled
        if ($this->blockJavaScript && $result['has_javascript']) {
            SecurityLogger::logFileEvent(
                $value,
                SecurityLogger::EVENT_PDF_THREAT,
                SecurityLogger::LEVEL_MEDIUM,
                'JavaScript detected in PDF file',
                [
                    'attribute' => $attribute,
                    'blocked_by' => 'blockJavaScript',
                ]
            );

            $fail("The {$attribute} contains JavaScript code. Please remove JavaScript before uploading.");
            return;
        }

        // Check for external links if blocking is enabled
        if ($this->blockExternalLinks && $result['has_external_links']) {
            SecurityLogger::logFileEvent(
                $value,
                SecurityLogger::EVENT_PDF_THREAT,
                SecurityLogger::LEVEL_LOW,
                'External links detected in PDF file',
                [
                    'attribute' => $attribute,
                    'blocked_by' => 'blockExternalLinks',
                ]
            );

            $fail("The {$attribute} contains external links. Please remove external links before uploading.");
            return;
        }
    }

    /**
     * Show threat details in validation error message
     *
     * @return self
     */
    public function withThreats(): self
    {
        $this->showThreats = true;
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
}
