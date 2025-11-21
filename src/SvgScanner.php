<?php

namespace Abdian\LaravelSafeguard;

use Illuminate\Http\UploadedFile;

/**
 * SvgScanner - Scans SVG files for malicious content
 *
 * SVG files can contain dangerous JavaScript code, event handlers, and
 * embedded scripts that can lead to XSS attacks. This scanner detects
 * these security threats.
 */
class SvgScanner
{
    /**
     * Dangerous XML/SVG tags
     *
     * @var array<string>
     */
    protected array $dangerousTags = [
        'script',
        'iframe',
        'embed',
        'object',
        'use',         // Can load external resources
        'foreignObject', // Can embed HTML
        'animate',     // Can trigger events
        'animateTransform',
        'set',
    ];

    /**
     * Dangerous event handlers
     *
     * @var array<string>
     */
    protected array $dangerousAttributes = [
        'onload',
        'onclick',
        'onmouseover',
        'onmouseout',
        'onmousemove',
        'onmouseenter',
        'onmouseleave',
        'onfocus',
        'onblur',
        'onchange',
        'oninput',
        'onsubmit',
        'onkeydown',
        'onkeyup',
        'onkeypress',
        'onerror',
        'onabort',
        'onresize',
        'onscroll',
        'onbegin',
        'onend',
        'onrepeat',
    ];

    /**
     * Dangerous protocols in href/xlink:href
     *
     * @var array<string>
     */
    protected array $dangerousProtocols = [
        'javascript:',
        'data:text/html',
        'vbscript:',
    ];

    /**
     * Scan an SVG file for malicious content
     *
     * @param UploadedFile|string $file The SVG file to scan
     * @return array{safe: bool, threats: array<string>} Scan result
     */
    public function scan(UploadedFile|string $file): array
    {
        $path = $file instanceof UploadedFile ? $file->getRealPath() : $file;

        if (!file_exists($path) || !is_readable($path)) {
            return ['safe' => false, 'threats' => ['File cannot be read']];
        }

        // Read file content
        $content = file_get_contents($path);
        if ($content === false) {
            return ['safe' => false, 'threats' => ['Failed to read file content']];
        }

        // Check if it's actually an SVG file
        if (!$this->isSvgFile($content)) {
            return ['safe' => false, 'threats' => ['Not a valid SVG file']];
        }

        $threats = [];

        // Get configuration
        $customTags = config('safeguard.svg_scanning.custom_dangerous_tags', []);
        $customAttributes = config('safeguard.svg_scanning.custom_dangerous_attributes', []);
        $excludeTags = config('safeguard.svg_scanning.exclude_tags', []);
        $excludeAttributes = config('safeguard.svg_scanning.exclude_attributes', []);

        $allTags = array_diff(
            array_merge($this->dangerousTags, $customTags),
            $excludeTags
        );

        $allAttributes = array_diff(
            array_merge($this->dangerousAttributes, $customAttributes),
            $excludeAttributes
        );

        // Scan for dangerous tags
        $tagThreats = $this->scanForDangerousTags($content, $allTags);
        if (!empty($tagThreats)) {
            $threats = array_merge($threats, $tagThreats);
        }

        // Scan for event handlers
        $eventThreats = $this->scanForEventHandlers($content, $allAttributes);
        if (!empty($eventThreats)) {
            $threats = array_merge($threats, $eventThreats);
        }

        // Scan for dangerous protocols
        $protocolThreats = $this->scanForDangerousProtocols($content);
        if (!empty($protocolThreats)) {
            $threats = array_merge($threats, $protocolThreats);
        }

        // Scan for encoded/obfuscated content
        $obfuscationThreats = $this->scanForObfuscation($content);
        if (!empty($obfuscationThreats)) {
            $threats = array_merge($threats, $obfuscationThreats);
        }

        return [
            'safe' => empty($threats),
            'threats' => array_unique($threats),
        ];
    }

    /**
     * Check if content is a valid SVG file
     *
     * @param string $content File content
     * @return bool True if valid SVG
     */
    protected function isSvgFile(string $content): bool
    {
        // Check for SVG opening tag
        return preg_match('/<svg[^>]*>/i', $content) === 1;
    }

    /**
     * Scan for dangerous XML/SVG tags
     *
     * @param string $content SVG content
     * @param array<string> $tags Dangerous tags to check
     * @return array<string> Found threats
     */
    protected function scanForDangerousTags(string $content, array $tags): array
    {
        $threats = [];

        foreach ($tags as $tag) {
            // Match opening or self-closing tags
            $pattern = '/<' . preg_quote($tag, '/') . '[\s>\/]/i';

            if (preg_match($pattern, $content)) {
                $threats[] = "Dangerous tag detected: <{$tag}>";
            }
        }

        return $threats;
    }

    /**
     * Scan for event handler attributes
     *
     * @param string $content SVG content
     * @param array<string> $attributes Dangerous attributes to check
     * @return array<string> Found threats
     */
    protected function scanForEventHandlers(string $content, array $attributes): array
    {
        $threats = [];

        foreach ($attributes as $attribute) {
            // Match attribute with any value
            $pattern = '/' . preg_quote($attribute, '/') . '\s*=\s*["\'][^"\']*["\']/i';

            if (preg_match($pattern, $content)) {
                $threats[] = "Event handler detected: {$attribute}";
            }
        }

        return $threats;
    }

    /**
     * Scan for dangerous protocols in hrefs
     *
     * @param string $content SVG content
     * @return array<string> Found threats
     */
    protected function scanForDangerousProtocols(string $content): array
    {
        $threats = [];

        foreach ($this->dangerousProtocols as $protocol) {
            // Check in href and xlink:href attributes
            $pattern = '/(href|xlink:href)\s*=\s*["\']' . preg_quote($protocol, '/') . '/i';

            if (preg_match($pattern, $content)) {
                $threats[] = "Dangerous protocol detected: {$protocol}";
            }
        }

        return $threats;
    }

    /**
     * Scan for obfuscated or encoded content
     *
     * @param string $content SVG content
     * @return array<string> Found threats
     */
    protected function scanForObfuscation(string $content): array
    {
        $threats = [];

        // Check for base64 encoded content
        if (preg_match('/data:image\/svg\+xml;base64,/i', $content)) {
            $threats[] = 'Base64 encoded SVG content detected';
        }

        // Check for URL encoded event handlers
        if (preg_match('/%6F%6E|%3Cscript/i', $content)) {
            $threats[] = 'URL encoded suspicious content detected';
        }

        // Check for HTML entities obfuscation
        if (preg_match('/&#(x?[0-9a-f]+);.*script/i', $content)) {
            $threats[] = 'HTML entity obfuscation detected';
        }

        // Check for CDATA sections (can hide scripts)
        if (preg_match('/<!\[CDATA\[.*script/is', $content)) {
            $threats[] = 'CDATA section with script detected';
        }

        return $threats;
    }

    /**
     * Check if file is SVG (quick MIME type check)
     *
     * @param UploadedFile|string $file The file to check
     * @return bool True if SVG
     */
    public function isSvg(UploadedFile|string $file): bool
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

        return $this->isSvgFile($content);
    }
}
