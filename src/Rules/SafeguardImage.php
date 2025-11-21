<?php

namespace Abdian\LaravelSafeguard\Rules;

use Abdian\LaravelSafeguard\ImageScanner;
use Closure;
use Illuminate\Contracts\Validation\ValidationRule;
use Illuminate\Http\UploadedFile;

/**
 * SafeguardImage - Validates that images don't contain hidden malicious content
 *
 * This validation rule scans images for:
 * - PHP code hidden in EXIF metadata
 * - Malicious code in trailing bytes
 * - Suspicious shell commands in metadata
 * - GPS location data (privacy concern)
 *
 * Usage:
 *   'avatar' => ['required', new SafeguardImage()]
 *
 * Or via string rule:
 *   'avatar' => 'required|safeguard_image'
 */
class SafeguardImage implements ValidationRule
{
    /**
     * Image scanner instance
     *
     * @var ImageScanner
     */
    protected ImageScanner $scanner;

    /**
     * Whether to include threat details in error message
     *
     * @var bool
     */
    protected bool $showThreats;

    /**
     * Whether to fail validation if GPS data is found
     *
     * @var bool
     */
    protected bool $blockGps;

    /**
     * Whether to strip metadata and save cleaned image
     *
     * @var bool
     */
    protected bool $stripMetadata;

    /**
     * Create a new rule instance
     *
     * @param bool $showThreats Whether to show threat details in error message
     */
    public function __construct(bool $showThreats = false)
    {
        $this->scanner = new ImageScanner();
        $this->showThreats = $showThreats;
        $this->blockGps = false;
        $this->stripMetadata = false;
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

        // Check if image scanning is enabled
        if (!config('safeguard.image_scanning.enabled', true)) {
            return; // Skip scanning if disabled
        }

        // Check if file is actually an image
        if (!$this->scanner->isImage($value)) {
            $fail("The {$attribute} is not a valid image file.");
            return;
        }

        // Get GPS checking preference
        $checkGps = $this->blockGps || config('safeguard.image_scanning.check_gps', true);

        // Scan the image for malicious content
        $result = $this->scanner->scan($value, $checkGps);

        // Check for security threats
        if (!$result['safe']) {
            // Log the security incident
            logger()->warning('Malicious content detected in uploaded image', [
                'attribute' => $attribute,
                'filename' => $value->getClientOriginalName(),
                'threats' => $result['threats'],
                'has_gps' => $result['has_gps'],
                'metadata' => $result['metadata'],
                'ip' => request()->ip(),
            ]);

            // Build error message
            if ($this->showThreats && !empty($result['threats'])) {
                $threatList = implode(', ', array_slice($result['threats'], 0, 3));
                $fail("The {$attribute} contains malicious content: {$threatList}");
            } else {
                $fail("The {$attribute} contains potentially malicious content and cannot be uploaded.");
            }
            return;
        }

        // Check for GPS data if blocking is enabled
        if ($this->blockGps && $result['has_gps']) {
            logger()->info('GPS data found in uploaded image', [
                'attribute' => $attribute,
                'filename' => $value->getClientOriginalName(),
                'ip' => request()->ip(),
            ]);

            $fail("The {$attribute} contains GPS location data. Please remove location information before uploading.");
            return;
        }

        // Strip metadata if requested
        if ($this->stripMetadata && config('safeguard.image_scanning.auto_strip_metadata', false)) {
            $this->stripImageMetadata($value);
        }
    }

    /**
     * Strip metadata from the uploaded image
     *
     * @param UploadedFile $file The uploaded file
     * @return void
     */
    protected function stripImageMetadata(UploadedFile $file): void
    {
        $originalPath = $file->getRealPath();
        $tempPath = $originalPath . '.cleaned';

        if ($this->scanner->stripMetadata($file, $tempPath)) {
            // Replace original file with cleaned version
            @unlink($originalPath);
            @rename($tempPath, $originalPath);
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
     * Automatically strip metadata from uploaded images
     *
     * @return self
     */
    public function stripMetadata(): self
    {
        $this->stripMetadata = true;
        return $this;
    }
}
