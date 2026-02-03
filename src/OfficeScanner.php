<?php

namespace Abdian\LaravelSafeguard;

use Abdian\LaravelSafeguard\Concerns\ValidatesFileAccess;
use Illuminate\Http\UploadedFile;
use ZipArchive;

/**
 * OfficeScanner - Scans Office documents for macros and security threats
 *
 * Detects VBA macros and other security threats in Office Open XML documents:
 * - DOCX, XLSX, PPTX (and their macro-enabled variants)
 * - vbaProject.bin detection
 * - Content Types macro detection
 * - ActiveX control detection
 * - Extension spoofing detection
 */
class OfficeScanner
{
    use ValidatesFileAccess;

    /**
     * Office MIME types for Open XML formats
     *
     * @var array<string, string>
     */
    protected array $officeMimeTypes = [
        'docx' => 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
        'xlsx' => 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
        'pptx' => 'application/vnd.openxmlformats-officedocument.presentationml.presentation',
        'docm' => 'application/vnd.ms-word.document.macroEnabled.12',
        'xlsm' => 'application/vnd.ms-excel.sheet.macroEnabled.12',
        'pptm' => 'application/vnd.ms-powerpoint.presentation.macroEnabled.12',
    ];

    /**
     * Content types that indicate macro presence
     *
     * @var array<string>
     */
    protected array $macroContentTypes = [
        'application/vnd.ms-office.vbaProject',
        'application/vnd.ms-word.document.macroEnabled',
        'application/vnd.ms-excel.sheet.macroEnabled',
        'application/vnd.ms-powerpoint.presentation.macroEnabled',
        'application/vnd.ms-excel.sheet.macroEnabled.main+xml',
        'application/vnd.ms-word.document.macroEnabled.main+xml',
        'application/vnd.ms-powerpoint.presentation.macroEnabled.main+xml',
    ];

    /**
     * Macro-enabled extensions
     *
     * @var array<string>
     */
    protected array $macroExtensions = ['docm', 'xlsm', 'pptm', 'dotm', 'xltm', 'potm'];

    /**
     * Regular (non-macro) extensions
     *
     * @var array<string>
     */
    protected array $regularExtensions = ['docx', 'xlsx', 'pptx', 'dotx', 'xltx', 'potx'];

    /**
     * Whether to block macros
     *
     * @var bool
     */
    protected bool $blockMacros = true;

    /**
     * Whether to block ActiveX
     *
     * @var bool
     */
    protected bool $blockActiveX = true;

    /**
     * Scan an Office document for security threats
     *
     * @param UploadedFile|string $file The Office document to scan
     * @return array{safe: bool, threats: array<string>, has_macros: bool, has_activex: bool} Scan result
     */
    public function scan(UploadedFile|string $file): array
    {
        $path = $file instanceof UploadedFile ? $file->getRealPath() : $file;
        $originalName = $file instanceof UploadedFile ? $file->getClientOriginalName() : basename($path);

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

        // Check if file is a valid Office Open XML document (ZIP format)
        if (!$this->isOfficeDocument($path)) {
            return $this->failResult(['File is not a valid Office document']);
        }

        $threats = [];
        $hasMacros = false;
        $hasActiveX = false;

        $zip = new ZipArchive();
        if ($zip->open($path, ZipArchive::RDONLY) !== true) {
            return $this->failResult(['Failed to open Office document']);
        }

        // Check for vbaProject.bin (VBA macro storage)
        $vbaResult = $this->checkForVbaProject($zip);
        if ($vbaResult['found']) {
            $hasMacros = true;
            if ($this->blockMacros) {
                $threats[] = "VBA macro detected: {$vbaResult['location']}";
            }
        }

        // Check [Content_Types].xml for macro indicators
        $contentTypesResult = $this->checkContentTypes($zip);
        if ($contentTypesResult['has_macros']) {
            $hasMacros = true;
            if ($this->blockMacros) {
                foreach ($contentTypesResult['macro_types'] as $type) {
                    $threats[] = "Macro content type detected: {$type}";
                }
            }
        }

        // Check for ActiveX controls
        if ($this->blockActiveX) {
            $activeXResult = $this->checkForActiveX($zip);
            if ($activeXResult['found']) {
                $hasActiveX = true;
                $threats[] = "ActiveX control detected: {$activeXResult['count']} control(s)";
            }
        }

        $zip->close();

        // Check for extension spoofing
        $extension = strtolower(pathinfo($originalName, PATHINFO_EXTENSION));
        if ($hasMacros && in_array($extension, $this->regularExtensions, true)) {
            $threats[] = "Macro-enabled document disguised as .{$extension}";
        }

        return [
            'safe' => empty($threats),
            'threats' => array_unique($threats),
            'has_macros' => $hasMacros,
            'has_activex' => $hasActiveX,
        ];
    }

    /**
     * Check for vbaProject.bin in the archive
     *
     * @param ZipArchive $zip The opened ZIP archive
     * @return array{found: bool, location: string|null}
     */
    protected function checkForVbaProject(ZipArchive $zip): array
    {
        $vbaLocations = [
            'word/vbaProject.bin',
            'xl/vbaProject.bin',
            'ppt/vbaProject.bin',
            'vbaProject.bin',
        ];

        foreach ($vbaLocations as $location) {
            if ($zip->locateName($location) !== false) {
                return ['found' => true, 'location' => $location];
            }
        }

        // Also check for vbaProject.bin in any subdirectory
        for ($i = 0; $i < $zip->numFiles; $i++) {
            $fileName = $zip->getNameIndex($i);
            if ($fileName !== false && str_ends_with(strtolower($fileName), 'vbaproject.bin')) {
                return ['found' => true, 'location' => $fileName];
            }
        }

        return ['found' => false, 'location' => null];
    }

    /**
     * Check [Content_Types].xml for macro indicators
     *
     * @param ZipArchive $zip The opened ZIP archive
     * @return array{has_macros: bool, macro_types: array<string>}
     */
    protected function checkContentTypes(ZipArchive $zip): array
    {
        $contentTypesXml = $zip->getFromName('[Content_Types].xml');

        if ($contentTypesXml === false) {
            return ['has_macros' => false, 'macro_types' => []];
        }

        $foundMacroTypes = [];

        foreach ($this->macroContentTypes as $macroType) {
            if (stripos($contentTypesXml, $macroType) !== false) {
                $foundMacroTypes[] = $macroType;
            }
        }

        return [
            'has_macros' => !empty($foundMacroTypes),
            'macro_types' => $foundMacroTypes,
        ];
    }

    /**
     * Check for ActiveX controls in the document
     *
     * @param ZipArchive $zip The opened ZIP archive
     * @return array{found: bool, count: int}
     */
    protected function checkForActiveX(ZipArchive $zip): array
    {
        $activeXCount = 0;

        for ($i = 0; $i < $zip->numFiles; $i++) {
            $fileName = $zip->getNameIndex($i);
            if ($fileName === false) {
                continue;
            }

            // Check for activeX directory or files
            if (preg_match('/activex[\/\\\\]activex\d*\.(xml|bin)/i', $fileName)) {
                $activeXCount++;
            }

            // Check for oleObject (embedded OLE)
            if (preg_match('/embeddings[\/\\\\]oleObject\d*\.bin/i', $fileName)) {
                $activeXCount++;
            }
        }

        return [
            'found' => $activeXCount > 0,
            'count' => $activeXCount,
        ];
    }

    /**
     * Check if file is a valid Office Open XML document
     *
     * @param string $path Path to file
     * @return bool
     */
    public function isOfficeDocument(string $path): bool
    {
        // Check if it's a valid ZIP file first
        $zip = new ZipArchive();
        if ($zip->open($path, ZipArchive::RDONLY) !== true) {
            return false;
        }

        // Check for [Content_Types].xml (required in all Office Open XML)
        $hasContentTypes = $zip->locateName('[Content_Types].xml') !== false;

        // Check for common Office directories
        $hasWordDir = $zip->locateName('word/') !== false || $zip->locateName('word/document.xml') !== false;
        $hasExcelDir = $zip->locateName('xl/') !== false || $zip->locateName('xl/workbook.xml') !== false;
        $hasPptDir = $zip->locateName('ppt/') !== false || $zip->locateName('ppt/presentation.xml') !== false;

        $zip->close();

        return $hasContentTypes && ($hasWordDir || $hasExcelDir || $hasPptDir);
    }

    /**
     * Check if file is a legacy Office format
     *
     * @param string $path Path to file
     * @return bool
     */
    public function isLegacyOfficeFormat(string $path): bool
    {
        $handle = fopen($path, 'rb');
        if ($handle === false) {
            return false;
        }

        $header = fread($handle, 8);
        fclose($handle);

        if ($header === false || strlen($header) < 8) {
            return false;
        }

        // OLE Compound Document header: D0 CF 11 E0 A1 B1 1A E1
        return str_starts_with($header, "\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1");
    }

    /**
     * Load configuration from Laravel config
     *
     * @return void
     */
    protected function loadConfiguration(): void
    {
        $this->blockMacros = $this->getOfficeConfig('block_macros', true);
        $this->blockActiveX = $this->getOfficeConfig('block_activex', true);

        $allowedMacroExtensions = $this->getOfficeConfig('allowed_macro_extensions', []);
        if (!empty($allowedMacroExtensions)) {
            // Remove allowed extensions from the "regular" list that would trigger spoofing detection
            $this->regularExtensions = array_diff($this->regularExtensions, $allowedMacroExtensions);
        }
    }

    /**
     * Get office configuration value
     *
     * @param string $key Configuration key
     * @param mixed $default Default value
     * @return mixed
     */
    protected function getOfficeConfig(string $key, mixed $default = null): mixed
    {
        if (function_exists('config') && function_exists('app')) {
            try {
                return config("safeguard.office_scanning.{$key}", $default) ?? $default;
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
     * @return array{safe: bool, threats: array<string>, has_macros: bool, has_activex: bool}
     */
    protected function failResult(array $threats): array
    {
        return [
            'safe' => false,
            'threats' => $threats,
            'has_macros' => false,
            'has_activex' => false,
        ];
    }

    /**
     * Enable or disable macro blocking
     *
     * @param bool $block Whether to block macros
     * @return self
     */
    public function blockMacros(bool $block = true): self
    {
        $this->blockMacros = $block;
        return $this;
    }

    /**
     * Enable or disable ActiveX blocking
     *
     * @param bool $block Whether to block ActiveX
     * @return self
     */
    public function blockActiveX(bool $block = true): self
    {
        $this->blockActiveX = $block;
        return $this;
    }

    /**
     * Allow macros (disable blocking)
     *
     * @return self
     */
    public function allowMacros(): self
    {
        $this->blockMacros = false;
        return $this;
    }

    /**
     * Allow ActiveX (disable blocking)
     *
     * @return self
     */
    public function allowActiveX(): self
    {
        $this->blockActiveX = false;
        return $this;
    }
}
