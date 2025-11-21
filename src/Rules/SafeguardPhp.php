<?php

namespace Abdian\LaravelSafeguard\Rules;

use Abdian\LaravelSafeguard\PhpCodeScanner;
use Closure;
use Illuminate\Contracts\Validation\ValidationRule;
use Illuminate\Http\UploadedFile;

/**
 * SafeguardPhp - Validates that uploaded files don't contain malicious PHP code
 *
 * This validation rule scans files for dangerous PHP code patterns including:
 * - PHP opening tags (<?php, <?, <?=)
 * - Dangerous functions (eval, exec, system, etc.)
 * - Obfuscated code (base64_decode, gzinflate, etc.)
 * - Web shell patterns
 *
 * Usage:
 *   'file' => ['required', new SafeguardPhp()]
 *
 * Or via string rule:
 *   'file' => 'required|safeguard_php'
 */
class SafeguardPhp implements ValidationRule
{
    /**
     * PHP code scanner instance
     *
     * @var PhpCodeScanner
     */
    protected PhpCodeScanner $scanner;

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
        $this->scanner = new PhpCodeScanner();
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

        // Check if PHP scanning is enabled
        if (!config('safeguard.php_scanning.enabled', true)) {
            return; // Skip scanning if disabled
        }

        // Scan the file for malicious PHP code
        $result = $this->scanner->scan($value);

        if (!$result['safe']) {
            // Log the security incident
            logger()->warning('Malicious PHP code detected in uploaded file', [
                'attribute' => $attribute,
                'filename' => $value->getClientOriginalName(),
                'threats' => $result['threats'],
                'ip' => request()->ip(),
            ]);

            // Build error message
            if ($this->showThreats && !empty($result['threats'])) {
                $threatList = implode(', ', array_slice($result['threats'], 0, 3));
                $fail("The {$attribute} contains malicious code: {$threatList}");
            } else {
                $fail("The {$attribute} contains potentially malicious code and cannot be uploaded.");
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
