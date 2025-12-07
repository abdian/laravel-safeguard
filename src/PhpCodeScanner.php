<?php

namespace Abdian\LaravelSafeguard;

use Illuminate\Http\UploadedFile;

/**
 * PhpCodeScanner - Scans files for malicious PHP code patterns
 *
 * This class detects dangerous PHP functions and patterns that are commonly
 * used in web shells, backdoors, and other malicious scripts.
 */
class PhpCodeScanner
{
    /**
     * Dangerous PHP functions that are commonly used in attacks
     *
     * @var array<string>
     */
    protected array $dangerousFunctions = [
        // Code execution
        'eval',
        'assert',
        'create_function',
        'call_user_func',
        'call_user_func_array',

        // System command execution
        'exec',
        'shell_exec',
        'system',
        'passthru',
        'popen',
        'proc_open',
        'pcntl_exec',

        // File operations (can be dangerous)
        'file_put_contents',
        'file_get_contents',
        'fopen',
        'fwrite',
        'fputs',

        // Obfuscation/encoding
        'base64_decode',
        'gzinflate',
        'gzuncompress',
        'str_rot13',
        'convert_uudecode',

        // Include/require (can load remote files)
        'include',
        'include_once',
        'require',
        'require_once',

        // Dangerous variable functions
        'extract',
        'parse_str',
        'preg_replace', // With /e modifier
        'mb_ereg_replace',

        // Other dangerous functions
        'move_uploaded_file',
        'copy',
        'rename',
        'unlink',
        'chmod',
        'chown',
        'chgrp',
    ];

    /**
     * Suspicious patterns commonly found in malicious code
     *
     * @var array<string>
     */
    protected array $suspiciousPatterns = [
        // PHP opening tags (removed - handled separately in scanForPhpTags())

        // Script tags with PHP language
        '/<script[^>]*language\s*=\s*["\']?php["\']?[^>]*>/i',
        '/<%(.*?)%>/is',

        // Web shell patterns (specific known patterns)
        '/\bc99\s+shell\b/i',
        '/\br57\s+shell\b/i',
        '/\bb374k\b/i',
        '/\bwso\s+shell\b/i',
        '/\bFilesMan\b/i',
        '/\bSafe0ver\b/i',
        '/\bTryag\s+File\s+Manager\b/i',
        '/\bAngel\s+Shell\b/i',

        // Dangerous combinations (high confidence threats)
        '/eval\s*\(\s*base64_decode/i',
        '/eval\s*\(\s*gzinflate/i',
        '/assert\s*\(\s*base64_decode/i',
        '/assert\s*\(\s*gzinflate/i',
        '/preg_replace\s*\([^)]*\/[a-z]*e[a-z]*["\'\)]/i', // preg_replace with /e modifier

        // Hex-encoded PHP tags (very suspicious)
        '/\\\\x3c\\\\x3f/i', // \x3c\x3f = <?
    ];

    /**
     * Scan a file for malicious PHP code
     *
     * @param UploadedFile|string $file The file to scan
     * @return array{safe: bool, threats: array<string>} Scan result
     */
    public function scan(UploadedFile|string $file): array
    {
        $path = $file instanceof UploadedFile ? $file->getRealPath() : $file;

        if (!file_exists($path) || !is_readable($path)) {
            return ['safe' => false, 'threats' => ['File cannot be read']];
        }

        // Skip PHP scanning for binary files (images, PDFs, videos, etc.)
        // These files cannot contain executable PHP code
        $detector = new MimeTypeDetector();
        if ($detector->isBinaryFile($file)) {
            return ['safe' => true, 'threats' => []];
        }

        // Read file content
        $content = file_get_contents($path);
        if ($content === false) {
            return ['safe' => false, 'threats' => ['Failed to read file content']];
        }

        $threats = [];

        // Get configuration
        $mode = config('safeguard.php_scanning.mode', 'default');
        $scanFunctions = config('safeguard.php_scanning.scan_functions', []);
        $customFunctions = config('safeguard.php_scanning.custom_dangerous_functions', []);
        $excludeFunctions = config('safeguard.php_scanning.exclude_functions', []);
        $customPatterns = config('safeguard.php_scanning.custom_patterns', []);
        $excludePatterns = config('safeguard.php_scanning.exclude_patterns', []);

        // Build functions list based on mode
        $allFunctions = $this->buildFunctionsList($mode, $scanFunctions, $customFunctions, $excludeFunctions);

        // Build patterns list
        $allPatterns = $this->buildPatternsList($customPatterns, $excludePatterns);

        // Scan for PHP opening tags
        $phpTagThreats = $this->scanForPhpTags($content);
        if (!empty($phpTagThreats)) {
            $threats = array_merge($threats, $phpTagThreats);
        }

        // Scan for dangerous functions
        $functionThreats = $this->scanForDangerousFunctions($content, $allFunctions);
        if (!empty($functionThreats)) {
            $threats = array_merge($threats, $functionThreats);
        }

        // Scan for suspicious patterns
        $patternThreats = $this->scanForSuspiciousPatterns($content, $allPatterns);
        if (!empty($patternThreats)) {
            $threats = array_merge($threats, $patternThreats);
        }

        return [
            'safe' => empty($threats),
            'threats' => array_unique($threats),
        ];
    }

    /**
     * Build functions list based on configuration mode
     *
     * @param string $mode Scan mode (default, strict, custom)
     * @param array<string> $scanFunctions Functions to scan for (custom mode)
     * @param array<string> $customFunctions Additional functions to add
     * @param array<string> $excludeFunctions Functions to exclude
     * @return array<string> Final list of functions to scan
     */
    protected function buildFunctionsList(string $mode, array $scanFunctions, array $customFunctions, array $excludeFunctions): array
    {
        $functions = [];

        switch ($mode) {
            case 'strict':
                // Only most dangerous functions
                $functions = [
                    'eval',
                    'assert',
                    'exec',
                    'shell_exec',
                    'system',
                    'passthru',
                    'proc_open',
                ];
                break;

            case 'custom':
                // Only user-specified functions
                $functions = $scanFunctions;
                break;

            case 'default':
            default:
                // Built-in list + custom additions
                $functions = array_merge($this->dangerousFunctions, $customFunctions);
                break;
        }

        // Remove excluded functions
        if (!empty($excludeFunctions)) {
            $functions = array_diff($functions, $excludeFunctions);
        }

        return array_values(array_unique($functions));
    }

    /**
     * Build patterns list
     *
     * @param array<string> $customPatterns Additional patterns to add
     * @param array<string> $excludePatterns Patterns to exclude
     * @return array<string> Final list of patterns to scan
     */
    protected function buildPatternsList(array $customPatterns, array $excludePatterns): array
    {
        $patterns = array_merge($this->suspiciousPatterns, $customPatterns);

        // Remove excluded patterns
        if (!empty($excludePatterns)) {
            foreach ($excludePatterns as $excludePattern) {
                $key = array_search($excludePattern, $patterns, true);
                if ($key !== false) {
                    unset($patterns[$key]);
                }
            }
        }

        return array_values($patterns);
    }

    /**
     * Scan for PHP opening tags
     *
     * @param string $content The file content
     * @return array<string> Found threats
     */
    protected function scanForPhpTags(string $content): array
    {
        $threats = [];

        // Check for PHP opening tags
        if (preg_match('/<\?php\s/i', $content)) {
            $threats[] = 'PHP opening tag (<?php) detected';
        }

        if (preg_match('/<\?=\s*[a-zA-Z$_]/i', $content)) {
            $threats[] = 'PHP short echo tag (<?=) detected';
        }

        // More strict short tag detection: must be followed by whitespace or variable
        // This reduces false positives from legitimate uses of "<?" in text
        if (preg_match('/<\?(?!xml\s|xml\?)(?:\s+[a-zA-Z$_])/i', $content)) {
            $threats[] = 'PHP short tag (<?) detected';
        }

        return $threats;
    }

    /**
     * Scan for dangerous PHP functions
     *
     * @param string $content The file content
     * @param array<string> $functions List of dangerous functions
     * @return array<string> Found threats
     */
    protected function scanForDangerousFunctions(string $content, array $functions): array
    {
        $threats = [];

        foreach ($functions as $function) {
            // Match function name followed by opening parenthesis
            $pattern = '/\b' . preg_quote($function, '/') . '\s*\(/i';

            if (preg_match($pattern, $content)) {
                $threats[] = "Dangerous function detected: {$function}()";
            }
        }

        return $threats;
    }

    /**
     * Scan for suspicious patterns
     *
     * @param string $content The file content
     * @param array<string> $patterns List of regex patterns
     * @return array<string> Found threats
     */
    protected function scanForSuspiciousPatterns(string $content, array $patterns): array
    {
        $threats = [];

        foreach ($patterns as $pattern) {
            if (@preg_match($pattern, $content)) {
                $threats[] = "Suspicious code pattern detected";
            }
        }

        return $threats;
    }

    /**
     * Check if file contains PHP code (quick check)
     *
     * @param UploadedFile|string $file The file to check
     * @return bool True if PHP code detected
     */
    public function containsPhpCode(UploadedFile|string $file): bool
    {
        $path = $file instanceof UploadedFile ? $file->getRealPath() : $file;

        if (!file_exists($path)) {
            return false;
        }

        // Read first 1KB for quick check
        $handle = fopen($path, 'rb');
        if ($handle === false) {
            return false;
        }

        $content = fread($handle, 1024);
        fclose($handle);

        if ($content === false) {
            return false;
        }

        // Quick check for PHP tags
        return preg_match('/<\?(?:php|=)?/i', $content) === 1;
    }
}
