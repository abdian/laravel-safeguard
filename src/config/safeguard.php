<?php

return [
    /*
    |--------------------------------------------------------------------------
    | MIME Type Validation
    |--------------------------------------------------------------------------
    */

    'mime_validation' => [
        // Fail if detected MIME type doesn't match client-provided type
        'strict_check' => env('SAFEGUARD_MIME_STRICT', true),

        // Automatically block dangerous file types (executables, scripts)
        'block_dangerous' => env('SAFEGUARD_MIME_BLOCK_DANGEROUS', true),

        // Custom magic bytes signatures for additional file types
        // Add your own file type signatures here
        // Format: 'hexadecimal_signature' => 'mime/type'
        'custom_signatures' => [
            // Example: 'cafebabe' => 'application/java-vm',
        ],

        // List of dangerous MIME types to block
        'dangerous_types' => [
            // Executables
            'application/x-msdownload',       // Windows .exe
            'application/x-msdos-program',    // DOS executables
            'application/x-executable',        // Linux executables
            'application/x-elf',               // ELF executables
            'application/x-sharedlib',         // Shared libraries
            'application/x-mach-binary',       // macOS executables
            'application/x-dosexec',           // DOS executables

            // Scripts
            'application/x-php',               // PHP files
            'text/x-php',                      // PHP files (alternative)
            'application/x-httpd-php',         // PHP files (server)
            'application/x-httpd-php-source',  // PHP source
            'text/x-shellscript',              // Shell scripts
            'application/x-sh',                // Shell scripts
            'application/x-csh',               // C Shell scripts
            'application/x-perl',              // Perl scripts
            'text/x-perl',                     // Perl scripts
            'application/x-python',            // Python scripts
            'text/x-python',                   // Python scripts
            'application/x-ruby',              // Ruby scripts
            'text/x-ruby',                     // Ruby scripts
            'text/x-jsp',                      // JSP files

            // Web scripts (can be dangerous in certain contexts)
            'application/javascript',          // JavaScript
            'text/javascript',                 // JavaScript
            'application/x-javascript',        // JavaScript

            // Other dangerous formats
            'application/x-bat',               // Windows batch files
            'application/x-msi',               // Windows installers
            'application/java-archive',        // JAR files (can contain malicious code)
        ],
    ],

    /*
    |--------------------------------------------------------------------------
    | PHP Code Scanning
    |--------------------------------------------------------------------------
    */

    'php_scanning' => [
        // Enable PHP code scanning
        'enabled' => env('SAFEGUARD_PHP_SCAN', true),

        // Scan mode: 'default', 'strict', 'custom'
        // - default: Use built-in dangerous functions list + custom additions
        // - strict: Only scan for explicitly dangerous functions (eval, exec, system)
        // - custom: Only scan for functions you specify in 'scan_functions'
        'mode' => 'default',

        // Functions to scan for (used when mode = 'custom')
        'scan_functions' => [
            // Example: 'eval', 'exec', 'system',
        ],

        // Additional dangerous functions to detect (added to built-in list)
        'custom_dangerous_functions' => [
            // Example: 'my_dangerous_function',
        ],

        // Functions to exclude from scanning (ignored even if in built-in list)
        'exclude_functions' => [
            // Example: 'file_get_contents', 'fopen',
        ],

        // Additional suspicious patterns (regex)
        'custom_patterns' => [
            // Example: '/my_pattern/i',
        ],

        // Patterns to exclude from scanning
        'exclude_patterns' => [
            // Example: '/base64_decode/i',
        ],
    ],

    /*
    |--------------------------------------------------------------------------
    | SVG Security Scanning
    |--------------------------------------------------------------------------
    */

    'svg_scanning' => [
        // Enable SVG security scanning
        'enabled' => env('SAFEGUARD_SVG_SCAN', true),

        // Additional dangerous tags to detect
        'custom_dangerous_tags' => [
            // Example: 'video', 'audio',
        ],

        // Tags to exclude from scanning
        'exclude_tags' => [
            // Example: 'use', 'animate',
        ],

        // Additional dangerous attributes to detect
        'custom_dangerous_attributes' => [
            // Example: 'onactivate', 'ontouchstart',
        ],

        // Attributes to exclude from scanning
        'exclude_attributes' => [
            // Example: 'onload',
        ],
    ],
];
