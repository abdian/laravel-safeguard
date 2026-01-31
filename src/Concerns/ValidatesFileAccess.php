<?php

namespace Abdian\LaravelSafeguard\Concerns;

/**
 * ValidatesFileAccess - Trait for validating file access security
 *
 * This trait provides methods to validate that files are safe to read:
 * - Rejects symbolic links (prevents TOCTOU attacks)
 * - Validates file paths are within allowed directories
 * - Prevents path traversal attacks
 */
trait ValidatesFileAccess
{
    /**
     * Validate that a file path is safe to access
     *
     * Checks:
     * 1. File is not a symbolic link
     * 2. File path resolves to a real path
     * 3. File is within allowed directories (if configured)
     *
     * @param string $path The file path to validate
     * @return bool True if safe to access, false otherwise
     */
    protected function validateFileAccess(string $path): bool
    {
        // Check if symlink checking is enabled (default: true)
        if ($this->getSecurityConfig('check_symlinks', true)) {
            // Reject symbolic links
            if (is_link($path)) {
                return false;
            }
        }

        // Ensure real path exists and can be resolved
        $realPath = realpath($path);
        if ($realPath === false) {
            return false;
        }

        // Check for null bytes in path (path injection attack)
        if (str_contains($path, "\0")) {
            return false;
        }

        // Validate path is within allowed directories
        $allowedPaths = $this->getSecurityConfig('allowed_upload_paths', null);

        // If no specific paths configured, use defaults
        if ($allowedPaths === null) {
            $allowedPaths = $this->getDefaultAllowedPaths();
        }

        // If still empty (non-Laravel environment), allow all paths
        if (empty($allowedPaths)) {
            return true;
        }

        // Check if file is within any allowed directory
        foreach ($allowedPaths as $allowedPath) {
            $realAllowedPath = realpath($allowedPath);
            if ($realAllowedPath === false) {
                continue;
            }

            // Normalize directory separators for cross-platform compatibility
            $normalizedRealPath = str_replace('\\', '/', $realPath);
            $normalizedAllowedPath = str_replace('\\', '/', $realAllowedPath);

            if (str_starts_with($normalizedRealPath, $normalizedAllowedPath)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Get the reason why file access validation failed
     *
     * @param string $path The file path that failed validation
     * @return string Human-readable reason for failure
     */
    protected function getFileAccessFailureReason(string $path): string
    {
        if ($this->getSecurityConfig('check_symlinks', true) && is_link($path)) {
            return 'Symbolic link detected';
        }

        if (str_contains($path, "\0")) {
            return 'Invalid path: null byte detected';
        }

        $realPath = realpath($path);
        if ($realPath === false) {
            return 'Unable to resolve file path';
        }

        return 'File path outside allowed directories';
    }

    /**
     * Get default allowed upload paths
     *
     * @return array<string> Default allowed paths
     */
    protected function getDefaultAllowedPaths(): array
    {
        $paths = [];

        // System temp directory
        $tempDir = sys_get_temp_dir();
        if (!empty($tempDir)) {
            $paths[] = $tempDir;
        }

        // Laravel storage directory (if available)
        if (function_exists('storage_path')) {
            try {
                $storagePath = storage_path('app');
                if (!empty($storagePath)) {
                    $paths[] = $storagePath;
                }
            } catch (\Throwable) {
                // Ignore if storage_path fails
            }
        }

        return $paths;
    }

    /**
     * Get security configuration value
     *
     * @param string $key Configuration key (without 'safeguard.security.' prefix)
     * @param mixed $default Default value if config not available
     * @return mixed Configuration value or default
     */
    protected function getSecurityConfig(string $key, mixed $default = null): mixed
    {
        if (function_exists('config') && function_exists('app')) {
            try {
                return config("safeguard.security.{$key}", $default) ?? $default;
            } catch (\Throwable) {
                return $default;
            }
        }
        return $default;
    }
}
