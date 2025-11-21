<?php

namespace Abdian\LaravelSafeguard\Rules;

use Closure;
use Illuminate\Contracts\Validation\ValidationRule;
use Illuminate\Http\UploadedFile;

/**
 * SafeguardPages - Validates PDF page count
 *
 * This validation rule checks PDF page count to prevent:
 * - Excessively large PDF files (performance issues)
 * - Empty PDFs (quality issues)
 * - DoS attacks via massive PDFs
 *
 * Usage:
 *   'document' => ['required', new SafeguardPages(1, 10)]  // min 1, max 10 pages
 *
 * Or via string rule:
 *   'document' => 'required|safeguard_pages:1,10'
 */
class SafeguardPages implements ValidationRule
{
    /**
     * Minimum number of pages
     *
     * @var int|null
     */
    protected ?int $minPages;

    /**
     * Maximum number of pages
     *
     * @var int|null
     */
    protected ?int $maxPages;

    /**
     * Create a new rule instance
     *
     * @param int|null $minPages Minimum number of pages
     * @param int|null $maxPages Maximum number of pages
     */
    public function __construct(?int $minPages = null, ?int $maxPages = null)
    {
        $this->minPages = $minPages;
        $this->maxPages = $maxPages;
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

        // Read file content
        $content = file_get_contents($value->getRealPath());
        if ($content === false) {
            $fail("The {$attribute} cannot be read.");
            return;
        }

        // Check if it's a PDF file
        if (!str_starts_with($content, '%PDF-')) {
            $fail("The {$attribute} is not a valid PDF file.");
            return;
        }

        // Count pages
        $pageCount = $this->countPdfPages($content);

        if ($pageCount === 0) {
            $fail("The {$attribute} page count cannot be determined.");
            return;
        }

        // Check minimum pages
        if ($this->minPages !== null && $pageCount < $this->minPages) {
            $fail("The {$attribute} must have at least {$this->minPages} page(s). Current: {$pageCount} page(s).");
            return;
        }

        // Check maximum pages
        if ($this->maxPages !== null && $pageCount > $this->maxPages) {
            $fail("The {$attribute} must not exceed {$this->maxPages} page(s). Current: {$pageCount} page(s).");
            return;
        }
    }

    /**
     * Count pages in PDF file
     *
     * This uses multiple methods to count pages for better accuracy
     *
     * @param string $content PDF file content
     * @return int Number of pages (0 if cannot determine)
     */
    protected function countPdfPages(string $content): int
    {
        $pageCount = 0;

        // Method 1: Count /Type /Page entries (most reliable for simple PDFs)
        if (preg_match_all('/\/Type[\s]*\/Page[^s]/i', $content, $matches)) {
            $pageCount = count($matches[0]);
        }

        // Method 2: Check /Count entry in /Pages object (more accurate for complex PDFs)
        if ($pageCount === 0) {
            if (preg_match('/\/Type[\s]*\/Pages.*?\/Count[\s]+(\d+)/is', $content, $matches)) {
                $pageCount = (int) $matches[1];
            }
        }

        // Method 3: Count page objects differently (fallback)
        if ($pageCount === 0) {
            if (preg_match_all('/\/Page\W/i', $content, $matches)) {
                $pageCount = count($matches[0]);
            }
        }

        return $pageCount;
    }

    /**
     * Set minimum pages
     *
     * @param int $pages Minimum number of pages
     * @return self
     */
    public function min(int $pages): self
    {
        $this->minPages = $pages;
        return $this;
    }

    /**
     * Set maximum pages
     *
     * @param int $pages Maximum number of pages
     * @return self
     */
    public function max(int $pages): self
    {
        $this->maxPages = $pages;
        return $this;
    }

    /**
     * Require exact number of pages
     *
     * @param int $pages Exact number of pages
     * @return self
     */
    public function exactly(int $pages): self
    {
        $this->minPages = $pages;
        $this->maxPages = $pages;
        return $this;
    }
}
