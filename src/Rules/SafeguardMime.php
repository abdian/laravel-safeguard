<?php

namespace Abdian\LaravelSafeguard\Rules;

use Abdian\LaravelSafeguard\MimeTypeDetector;
use Closure;
use Illuminate\Contracts\Validation\ValidationRule;
use Illuminate\Http\UploadedFile;
use Illuminate\Support\Str;

/**
 * SafeguardMime - Validates file MIME type based on actual file content, not extension
 *
 * This validation rule prevents file upload attacks by detecting the real MIME type
 * from magic bytes instead of trusting the file extension or client-provided MIME type.
 *
 * Usage:
 *   'file' => ['required', new SafeguardMime(['image/jpeg', 'image/png'])]
 *
 * Or via string rule:
 *   'file' => 'required|safeguard_mime:image/jpeg,image/png'
 */
class SafeguardMime implements ValidationRule
{
    /**
     * Allowed MIME types
     *
     * @var array<string>
     */
    protected array $allowedMimeTypes;

    /**
     * MIME type detector instance
     *
     * @var MimeTypeDetector
     */
    protected MimeTypeDetector $detector;

    /**
     * Whether to block dangerous file types automatically
     *
     * @var bool
     */
    protected bool $blockDangerous;

    /**
     * Create a new rule instance
     *
     * @param array|string $allowedMimeTypes Allowed MIME types (array or comma-separated string)
     * @param bool $blockDangerous Whether to automatically block dangerous files
     */
    public function __construct(array|string $allowedMimeTypes, bool $blockDangerous = true)
    {
        $this->allowedMimeTypes = is_array($allowedMimeTypes)
            ? $allowedMimeTypes
            : array_map('trim', explode(',', $allowedMimeTypes));

        $this->detector = new MimeTypeDetector();
        $this->blockDangerous = $blockDangerous;
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

        // Detect real MIME type from file content
        $detectedMimeType = $this->detector->detect($value);

        if ($detectedMimeType === null) {
            $fail("The {$attribute} file type could not be determined.");
            return;
        }

        // Check if detected type is dangerous
        if ($this->blockDangerous && $this->detector->isDangerous($detectedMimeType)) {
            $fail("The {$attribute} file type is not allowed for security reasons.");
            return;
        }

        // If no specific MIME types are required, allow all safe files
        if (empty($this->allowedMimeTypes)) {
            return; // File is safe (not dangerous), allow it
        }

        // Check if detected MIME type matches allowed types
        if (!$this->isAllowedMimeType($detectedMimeType)) {
            $allowedTypes = implode(', ', $this->allowedMimeTypes);
            $fail("The {$attribute} must be a file of type: {$allowedTypes}. Detected type: {$detectedMimeType}");
            return;
        }

        // Additional check: compare with client-provided MIME type
        $clientMimeType = $value->getMimeType();
        if (!$this->mimeTypesMatch($detectedMimeType, $clientMimeType)) {
            // Log potential attack attempt
            logger()->warning('File upload MIME type mismatch detected', [
                'attribute' => $attribute,
                'detected' => $detectedMimeType,
                'client_provided' => $clientMimeType,
                'original_name' => $value->getClientOriginalName(),
            ]);

            // Optionally fail validation based on config
            if (config('safeguard.mime_validation.strict_check', true)) {
                $fail("The {$attribute} file appears to have a fake extension or MIME type.");
                return;
            }
        }
    }

    /**
     * Check if detected MIME type is in the allowed list
     *
     * Supports wildcard matching (e.g., image/*) and Office format compatibility
     *
     * @param string $detectedMimeType The detected MIME type
     * @return bool True if MIME type is allowed
     */
    protected function isAllowedMimeType(string $detectedMimeType): bool
    {
        foreach ($this->allowedMimeTypes as $allowedType) {
            // Exact match
            if ($detectedMimeType === $allowedType) {
                return true;
            }

            // Wildcard match (e.g., image/* matches image/jpeg)
            if (str_ends_with($allowedType, '/*')) {
                $prefix = Str::before($allowedType, '/*');
                if (str_starts_with($detectedMimeType, $prefix . '/')) {
                    return true;
                }
            }

            // Check equivalent MIME types
            // Some systems detect Office files as ZIP, so we need to allow this
            if ($this->areEquivalentMimeTypes($detectedMimeType, $allowedType)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Check if two MIME types are equivalent
     *
     * Office Open XML formats (DOCX, XLSX, PPTX) are technically ZIP files,
     * so they may be detected as application/zip on some systems.
     *
     * @param string $detected The detected MIME type
     * @param string $allowed The allowed MIME type from the list
     * @return bool True if the types are equivalent
     */
    protected function areEquivalentMimeTypes(string $detected, string $allowed): bool
    {
        // Office formats that can be detected as ZIP
        $officeFormats = [
            'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
            'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
            'application/vnd.openxmlformats-officedocument.presentationml.presentation',
        ];

        // If user allows a specific Office format and we detected ZIP,
        // this is NOT a match (ZIP could be any archive)
        // The MimeTypeDetector should have refined this already
        // But if user allows ZIP and we detected an Office format, that's fine
        if ($allowed === 'application/zip' && in_array($detected, $officeFormats)) {
            return true;
        }

        return false;
    }

    /**
     * Check if detected and client-provided MIME types are compatible
     *
     * Some files may have slightly different MIME types from different sources,
     * but they represent the same file type.
     *
     * @param string $detected The detected MIME type
     * @param string|null $client The client-provided MIME type
     * @return bool True if types match or are compatible
     */
    protected function mimeTypesMatch(string $detected, ?string $client): bool
    {
        if ($client === null) {
            return true;
        }

        // Exact match
        if ($detected === $client) {
            return true;
        }

        // Check for known compatible types
        // Office Open XML formats (DOCX, XLSX, PPTX) are technically ZIP files,
        // so browsers/systems may report either the specific Office MIME or generic ZIP
        $compatibleTypes = [
            'image/jpeg' => ['image/jpg', 'image/pjpeg'],
            'image/jpg' => ['image/jpeg', 'image/pjpeg'],
            'application/zip' => [
                'application/x-zip-compressed',
                'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
                'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
                'application/vnd.openxmlformats-officedocument.presentationml.presentation',
            ],
            // Office formats can be reported as ZIP by some systems
            'application/vnd.openxmlformats-officedocument.wordprocessingml.document' => [
                'application/zip',
                'application/x-zip-compressed',
                'application/octet-stream',
            ],
            'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet' => [
                'application/zip',
                'application/x-zip-compressed',
                'application/octet-stream',
            ],
            'application/vnd.openxmlformats-officedocument.presentationml.presentation' => [
                'application/zip',
                'application/x-zip-compressed',
                'application/octet-stream',
            ],
        ];

        if (isset($compatibleTypes[$detected]) && in_array($client, $compatibleTypes[$detected])) {
            return true;
        }

        // Check reverse compatibility
        foreach ($compatibleTypes as $base => $compatible) {
            if ($detected === $base && in_array($client, $compatible)) {
                return true;
            }
            if ($client === $base && in_array($detected, $compatible)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Disable automatic blocking of dangerous file types
     *
     * @return self
     */
    public function allowDangerous(): self
    {
        $this->blockDangerous = false;
        return $this;
    }
}
