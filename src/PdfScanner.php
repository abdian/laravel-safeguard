<?php

namespace Abdian\LaravelSafeguard;

use Illuminate\Http\UploadedFile;

/**
 * PdfScanner - Scans PDF files for malicious content
 *
 * PDF files can contain JavaScript code, dangerous actions (launch external apps),
 * embedded files, and malicious URLs. This scanner detects these security threats.
 */
class PdfScanner
{
    /**
     * Dangerous PDF actions
     *
     * @var array<string>
     */
    protected array $dangerousActions = [
        '/Launch',           // Launch external application
        '/JavaScript',       // Execute JavaScript
        '/JS',              // JavaScript (short form)
        '/URI',             // Open URI (can be dangerous)
        '/SubmitForm',      // Submit form to external URL
        '/ImportData',      // Import data from external source
        '/GoToR',           // Go to remote destination
        '/GoToE',           // Go to embedded destination
        '/Sound',           // Embedded sound (can hide data)
        '/Movie',           // Embedded movie
        '/RichMedia',       // Rich media content
        '/EmbeddedFile',    // Embedded files
        '/FileAttachment',  // File attachments
    ];

    /**
     * Suspicious JavaScript functions in PDF
     *
     * @var array<string>
     */
    protected array $suspiciousJsFunctions = [
        'app.alert',
        'app.launchURL',
        'app.openDoc',
        'app.execMenuItem',
        'util.printf',
        'getURL',
        'submitForm',
        'importDataObject',
        'exportDataObject',
        'this.exportDataObject',
        'this.submitForm',
        'eval(',
        'unescape(',
        'String.fromCharCode',
    ];

    /**
     * Dangerous URL protocols
     *
     * @var array<string>
     */
    protected array $dangerousProtocols = [
        'javascript:',
        'file://',
        'vbscript:',
        'data:',
    ];

    /**
     * Scan a PDF file for malicious content
     *
     * @param UploadedFile|string $file The PDF file to scan
     * @return array{safe: bool, threats: array<string>, has_javascript: bool, has_external_links: bool} Scan result
     */
    public function scan(UploadedFile|string $file): array
    {
        $path = $file instanceof UploadedFile ? $file->getRealPath() : $file;

        if (!file_exists($path) || !is_readable($path)) {
            return ['safe' => false, 'threats' => ['File cannot be read'], 'has_javascript' => false, 'has_external_links' => false];
        }

        // Read file content
        $content = file_get_contents($path);
        if ($content === false) {
            return ['safe' => false, 'threats' => ['Failed to read file content'], 'has_javascript' => false, 'has_external_links' => false];
        }

        // Check if it's actually a PDF file
        if (!$this->isPdfFile($content)) {
            return ['safe' => false, 'threats' => ['Not a valid PDF file'], 'has_javascript' => false, 'has_external_links' => false];
        }

        $threats = [];
        $hasJavaScript = false;
        $hasExternalLinks = false;

        // Get configuration
        $customActions = config('safeguard.pdf_scanning.custom_dangerous_actions', []);
        $excludeActions = config('safeguard.pdf_scanning.exclude_actions', []);

        $allActions = array_diff(
            array_merge($this->dangerousActions, $customActions),
            $excludeActions
        );

        // Scan for dangerous PDF actions
        $actionThreats = $this->scanForDangerousActions($content, $allActions);
        if (!empty($actionThreats)) {
            $threats = array_merge($threats, $actionThreats);
        }

        // Scan for JavaScript
        $jsThreats = $this->scanForJavaScript($content);
        if (!empty($jsThreats)) {
            $threats = array_merge($threats, $jsThreats);
            $hasJavaScript = true;
        }

        // Scan for suspicious URLs
        $urlThreats = $this->scanForSuspiciousUrls($content);
        if (!empty($urlThreats)) {
            $threats = array_merge($threats, $urlThreats);
            $hasExternalLinks = true;
        }

        // Scan for obfuscated content
        $obfuscationThreats = $this->scanForObfuscation($content);
        if (!empty($obfuscationThreats)) {
            $threats = array_merge($threats, $obfuscationThreats);
        }

        // Scan for embedded files
        $embedThreats = $this->scanForEmbeddedFiles($content);
        if (!empty($embedThreats)) {
            $threats = array_merge($threats, $embedThreats);
        }

        return [
            'safe' => empty($threats),
            'threats' => array_unique($threats),
            'has_javascript' => $hasJavaScript,
            'has_external_links' => $hasExternalLinks,
        ];
    }

    /**
     * Check if content is a valid PDF file
     *
     * @param string $content File content
     * @return bool True if valid PDF
     */
    protected function isPdfFile(string $content): bool
    {
        // Check for PDF header
        return str_starts_with($content, '%PDF-');
    }

    /**
     * Scan for dangerous PDF actions
     *
     * @param string $content PDF content
     * @param array<string> $actions Dangerous actions to check
     * @return array<string> Found threats
     */
    protected function scanForDangerousActions(string $content, array $actions): array
    {
        $threats = [];

        foreach ($actions as $action) {
            // Match PDF action syntax
            if (preg_match('/' . preg_quote($action, '/') . '/i', $content)) {
                $actionName = trim($action, '/');
                $threats[] = "Dangerous PDF action detected: {$actionName}";
            }
        }

        return $threats;
    }

    /**
     * Scan for JavaScript in PDF
     *
     * @param string $content PDF content
     * @return array<string> Found threats
     */
    protected function scanForJavaScript(string $content): array
    {
        $threats = [];

        // Check for JavaScript keywords
        if (preg_match('/\/JavaScript|\/JS\s*<<|\/JS\s*\[/i', $content)) {
            $threats[] = 'JavaScript code detected in PDF';

            // Check for specific dangerous JS functions
            foreach ($this->suspiciousJsFunctions as $func) {
                $pattern = '/' . preg_quote($func, '/') . '/i';
                if (preg_match($pattern, $content)) {
                    $threats[] = "Suspicious JavaScript function detected: {$func}";
                }
            }
        }

        return $threats;
    }

    /**
     * Scan for suspicious URLs in PDF
     *
     * @param string $content PDF content
     * @return array<string> Found threats
     */
    protected function scanForSuspiciousUrls(string $content): array
    {
        $threats = [];

        // Check for dangerous protocols
        foreach ($this->dangerousProtocols as $protocol) {
            if (stripos($content, $protocol) !== false) {
                $threats[] = "Dangerous URL protocol detected: {$protocol}";
            }
        }

        // Check for external URLs in actions
        if (preg_match('/\/URI\s*\(/i', $content)) {
            $threats[] = 'External URL link detected in PDF';
        }

        // Check for form submission URLs
        if (preg_match('/\/SubmitForm.*?http/i', $content)) {
            $threats[] = 'Form submission to external URL detected';
        }

        return $threats;
    }

    /**
     * Scan for obfuscated content in PDF
     *
     * @param string $content PDF content
     * @return array<string> Found threats
     */
    protected function scanForObfuscation(string $content): array
    {
        $threats = [];

        // Check for heavily obfuscated streams
        if (preg_match_all('/\/Filter\s*\/FlateDecode/i', $content, $matches)) {
            $count = count($matches[0]);
            if ($count > 50) {
                $threats[] = "Suspicious amount of compressed streams detected ({$count})";
            }
        }

        // Check for hex-encoded strings (common in malicious PDFs)
        if (preg_match_all('/<[0-9a-fA-F\s]+>/s', $content, $matches)) {
            foreach ($matches[0] as $hex) {
                // Check if hex string is suspiciously long
                if (strlen($hex) > 500) {
                    $threats[] = 'Suspicious hex-encoded content detected';
                    break;
                }
            }
        }

        // Check for multiple encryption layers
        if (preg_match_all('/\/Encrypt/i', $content, $matches)) {
            $count = count($matches[0]);
            if ($count > 1) {
                $threats[] = 'Multiple encryption layers detected';
            }
        }

        return $threats;
    }

    /**
     * Scan for embedded files in PDF
     *
     * @param string $content PDF content
     * @return array<string> Found threats
     */
    protected function scanForEmbeddedFiles(string $content): array
    {
        $threats = [];

        // Check for embedded file streams
        if (preg_match('/\/EmbeddedFile/i', $content)) {
            $threats[] = 'Embedded file detected in PDF';

            // Check for executable embedded files
            if (preg_match('/\.exe|\.bat|\.cmd|\.scr|\.vbs/i', $content)) {
                $threats[] = 'Suspicious executable file embedded in PDF';
            }
        }

        // Check for file attachments
        if (preg_match('/\/FileAttachment/i', $content)) {
            $threats[] = 'File attachment detected in PDF';
        }

        return $threats;
    }

    /**
     * Check if file is PDF (quick check)
     *
     * @param UploadedFile|string $file The file to check
     * @return bool True if PDF
     */
    public function isPdf(UploadedFile|string $file): bool
    {
        $path = $file instanceof UploadedFile ? $file->getRealPath() : $file;

        if (!file_exists($path)) {
            return false;
        }

        // Read first 8 bytes for PDF header
        $handle = fopen($path, 'rb');
        if ($handle === false) {
            return false;
        }

        $header = fread($handle, 8);
        fclose($handle);

        if ($header === false) {
            return false;
        }

        return str_starts_with($header, '%PDF-');
    }

    /**
     * Extract PDF metadata (if available)
     *
     * @param UploadedFile|string $file The PDF file
     * @return array<string, mixed> Metadata
     */
    public function extractMetadata(UploadedFile|string $file): array
    {
        $path = $file instanceof UploadedFile ? $file->getRealPath() : $file;

        if (!file_exists($path) || !is_readable($path)) {
            return [];
        }

        $content = file_get_contents($path);
        if ($content === false) {
            return [];
        }

        $metadata = [];

        // Extract title
        if (preg_match('/\/Title\s*\((.*?)\)/s', $content, $matches)) {
            $metadata['title'] = trim($matches[1]);
        }

        // Extract author
        if (preg_match('/\/Author\s*\((.*?)\)/s', $content, $matches)) {
            $metadata['author'] = trim($matches[1]);
        }

        // Extract creator
        if (preg_match('/\/Creator\s*\((.*?)\)/s', $content, $matches)) {
            $metadata['creator'] = trim($matches[1]);
        }

        // Extract producer
        if (preg_match('/\/Producer\s*\((.*?)\)/s', $content, $matches)) {
            $metadata['producer'] = trim($matches[1]);
        }

        // Check PDF version
        if (preg_match('/%PDF-([\d\.]+)/', $content, $matches)) {
            $metadata['version'] = $matches[1];
        }

        return $metadata;
    }
}
