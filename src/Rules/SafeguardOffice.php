<?php

namespace Abdian\LaravelSafeguard\Rules;

use Closure;
use Illuminate\Contracts\Validation\ValidationRule;
use Illuminate\Http\UploadedFile;
use Abdian\LaravelSafeguard\OfficeScanner;
use Abdian\LaravelSafeguard\SecurityLogger;

/**
 * SafeguardOffice - Validates Office documents for macros and security threats
 *
 * Scans Office Open XML documents for:
 * - VBA macros (vbaProject.bin)
 * - Macro content types
 * - ActiveX controls
 * - Extension spoofing
 *
 * Usage:
 *   'file' => ['required', new SafeguardOffice()]
 *
 * Or via string rule:
 *   'file' => 'required|safeguard_office'
 *
 * To allow macros:
 *   'file' => 'required|safeguard_office:allow_macros'
 */
class SafeguardOffice implements ValidationRule
{
    /**
     * Whether to allow macros
     *
     * @var bool
     */
    protected bool $allowMacros = false;

    /**
     * Whether to allow ActiveX
     *
     * @var bool
     */
    protected bool $allowActiveX = false;

    /**
     * Create a new rule instance
     *
     * @param array<string> $parameters Rule parameters
     */
    public function __construct(array $parameters = [])
    {
        foreach ($parameters as $param) {
            if ($param === 'allow_macros') {
                $this->allowMacros = true;
            } elseif ($param === 'allow_activex') {
                $this->allowActiveX = true;
            }
        }
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
        if (!$value instanceof UploadedFile) {
            $fail("The {$attribute} must be a valid uploaded file.");
            return;
        }

        if (!$value->isValid()) {
            $fail("The {$attribute} upload failed.");
            return;
        }

        $scanner = new OfficeScanner();

        // Check if it's an Office document
        $path = $value->getRealPath();
        if (!$scanner->isOfficeDocument($path)) {
            // Check if it's a legacy format
            if ($scanner->isLegacyOfficeFormat($path)) {
                $fail("The {$attribute} uses legacy Office format. Cannot verify macro-free status.");
                return;
            }

            $fail("The {$attribute} must be a valid Office document.");
            return;
        }

        // Configure scanner
        if ($this->allowMacros) {
            $scanner->allowMacros();
        }

        if ($this->allowActiveX) {
            $scanner->allowActiveX();
        }

        $result = $scanner->scan($value);

        if (!$result['safe']) {
            // Log the security event
            SecurityLogger::logFileEvent(
                $value,
                SecurityLogger::EVENT_MACRO_DETECTED,
                SecurityLogger::LEVEL_HIGH,
                "Office document security threat detected in {$attribute}",
                [
                    'threats' => $result['threats'],
                    'has_macros' => $result['has_macros'],
                    'has_activex' => $result['has_activex'],
                ]
            );

            $fail("The {$attribute} contains security threats: " . implode(', ', array_slice($result['threats'], 0, 3)));
            return;
        }
    }

    /**
     * Allow macros in documents
     *
     * @return self
     */
    public function allowMacros(): self
    {
        $this->allowMacros = true;
        return $this;
    }

    /**
     * Allow ActiveX controls
     *
     * @return self
     */
    public function allowActiveX(): self
    {
        $this->allowActiveX = true;
        return $this;
    }

    /**
     * Block macros (default)
     *
     * @return self
     */
    public function blockMacros(): self
    {
        $this->allowMacros = false;
        return $this;
    }

    /**
     * Block ActiveX (default)
     *
     * @return self
     */
    public function blockActiveX(): self
    {
        $this->allowActiveX = false;
        return $this;
    }
}
