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
];
