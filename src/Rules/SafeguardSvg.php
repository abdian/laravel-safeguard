<?php

namespace Abdian\LaravelSafeguard\Rules;

use Abdian\LaravelSafeguard\SvgScanner;
use Closure;
use Illuminate\Contracts\Validation\ValidationRule;
use Illuminate\Http\UploadedFile;

/**
 * SafeguardSvg - Validates that SVG files don't contain malicious content
 *
 * This validation rule scans SVG files for XSS vectors including:
 * - <script> tags
 * - Event handlers (onclick, onload, etc.)
 * - Dangerous protocols (javascript:, data:)
 * - Obfuscated/encoded content
 * - Embedded objects and iframes
 *
 * Usage:
 *   'icon' => ['required', new SafeguardSvg()]
 *
 * Or via string rule:
 *   'icon' => 'required|safeguard_svg'
 */
class SafeguardSvg implements ValidationRule
{
    /**
     * SVG scanner instance
     *
     * @var SvgScanner
     */
    protected SvgScanner $scanner;

    /**
     * Whether to include threat details in error message
     *
     * @var bool
     */
    protected bool $showThreats;

    /**
     * Create a new rule instance
     *
     * @param bool $showThreats Whether to show threat details in error message
     */
    public function __construct(bool $showThreats = false)
    {
        $this->scanner = new SvgScanner();
        $this->showThreats = $showThreats;
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

        // Check if SVG scanning is enabled
        if (!config('safeguard.svg_scanning.enabled', true)) {
            return; // Skip scanning if disabled
        }

        // Scan the SVG file for malicious content
        $result = $this->scanner->scan($value);

        if (!$result['safe']) {
            // Log the security incident
            logger()->warning('Malicious SVG content detected in uploaded file', [
                'attribute' => $attribute,
                'filename' => $value->getClientOriginalName(),
                'threats' => $result['threats'],
                'ip' => request()->ip(),
            ]);

            // Build error message
            if ($this->showThreats && !empty($result['threats'])) {
                $threatList = implode(', ', array_slice($result['threats'], 0, 3));
                $fail("The {$attribute} contains malicious SVG content: {$threatList}");
            } else {
                $fail("The {$attribute} contains potentially malicious SVG content and cannot be uploaded.");
            }
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
}
