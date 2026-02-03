<?php

namespace Abdian\LaravelSafeguard\Rules;

use Closure;
use Illuminate\Contracts\Validation\ValidationRule;
use Illuminate\Http\UploadedFile;
use Abdian\LaravelSafeguard\ArchiveScanner;
use Abdian\LaravelSafeguard\SecurityLogger;

/**
 * SafeguardArchive - Validates archive files for security threats
 *
 * Scans archive contents for:
 * - Dangerous file extensions (PHP, EXE, etc.)
 * - Path traversal attacks
 * - Zip bombs (compression ratio check)
 * - Excessive file counts
 *
 * Usage:
 *   'file' => ['required', new SafeguardArchive()]
 *
 * Or via string rule:
 *   'file' => 'required|safeguard_archive'
 */
class SafeguardArchive implements ValidationRule
{
    /**
     * Extensions to allow (overrides blocked list)
     *
     * @var array<string>
     */
    protected array $allowedExtensions = [];

    /**
     * Additional extensions to block
     *
     * @var array<string>
     */
    protected array $additionalBlockedExtensions = [];

    /**
     * Create a new rule instance
     *
     * @param array<string> $parameters Rule parameters (e.g., allow_exe, allow_php)
     */
    public function __construct(array $parameters = [])
    {
        foreach ($parameters as $param) {
            if (str_starts_with($param, 'allow_')) {
                $this->allowedExtensions[] = substr($param, 6);
            } elseif (str_starts_with($param, 'block_')) {
                $this->additionalBlockedExtensions[] = substr($param, 6);
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

        $scanner = new ArchiveScanner();

        // Check if it's actually an archive
        if (!$scanner->isArchive($value)) {
            $fail("The {$attribute} must be a valid archive file.");
            return;
        }

        // Configure scanner with allowed/blocked extensions
        if (!empty($this->additionalBlockedExtensions)) {
            $scanner->addBlockedExtensions($this->additionalBlockedExtensions);
        }

        $result = $scanner->scan($value);

        if (!$result['safe']) {
            // Log the security event
            SecurityLogger::logFileEvent(
                $value,
                SecurityLogger::EVENT_ARCHIVE_THREAT,
                SecurityLogger::LEVEL_HIGH,
                "Archive security threat detected in {$attribute}",
                ['threats' => $result['threats']]
            );

            // Filter out threats for allowed extensions
            $filteredThreats = $this->filterAllowedExtensions($result['threats']);

            if (!empty($filteredThreats)) {
                $fail("The {$attribute} contains security threats: " . implode(', ', array_slice($filteredThreats, 0, 3)));
                return;
            }
        }
    }

    /**
     * Filter out threats for allowed extensions
     *
     * @param array<string> $threats Original threats
     * @return array<string> Filtered threats
     */
    protected function filterAllowedExtensions(array $threats): array
    {
        if (empty($this->allowedExtensions)) {
            return $threats;
        }

        return array_filter($threats, function ($threat) {
            foreach ($this->allowedExtensions as $ext) {
                if (stripos($threat, ".{$ext}") !== false) {
                    return false;
                }
            }
            return true;
        });
    }

    /**
     * Allow specific extensions
     *
     * @param array<string> $extensions Extensions to allow
     * @return self
     */
    public function allow(array $extensions): self
    {
        $this->allowedExtensions = array_merge($this->allowedExtensions, $extensions);
        return $this;
    }

    /**
     * Block additional extensions
     *
     * @param array<string> $extensions Extensions to block
     * @return self
     */
    public function block(array $extensions): self
    {
        $this->additionalBlockedExtensions = array_merge($this->additionalBlockedExtensions, $extensions);
        return $this;
    }
}
