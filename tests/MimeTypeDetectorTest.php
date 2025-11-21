<?php

namespace Abdian\LaravelSafeguard\Tests;

use Abdian\LaravelSafeguard\MimeTypeDetector;
use PHPUnit\Framework\TestCase;

/**
 * Tests for MimeTypeDetector class
 */
class MimeTypeDetectorTest extends TestCase
{
    protected MimeTypeDetector $detector;

    protected function setUp(): void
    {
        parent::setUp();
        $this->detector = new MimeTypeDetector();
    }

    /**
     * Test JPEG detection
     */
    public function test_detects_jpeg_files(): void
    {
        $testFile = $this->createTestFile("\xFF\xD8\xFF\xE0");
        $mimeType = $this->detector->detect($testFile);

        $this->assertEquals('image/jpeg', $mimeType);

        unlink($testFile);
    }

    /**
     * Test PNG detection
     */
    public function test_detects_png_files(): void
    {
        $testFile = $this->createTestFile("\x89\x50\x4E\x47\x0D\x0A\x1A\x0A");
        $mimeType = $this->detector->detect($testFile);

        $this->assertEquals('image/png', $mimeType);

        unlink($testFile);
    }

    /**
     * Test GIF detection
     */
    public function test_detects_gif_files(): void
    {
        $testFile = $this->createTestFile("GIF89a");
        $mimeType = $this->detector->detect($testFile);

        $this->assertEquals('image/gif', $mimeType);

        unlink($testFile);
    }

    /**
     * Test PDF detection
     */
    public function test_detects_pdf_files(): void
    {
        $testFile = $this->createTestFile("%PDF-");
        $mimeType = $this->detector->detect($testFile);

        $this->assertEquals('application/pdf', $mimeType);

        unlink($testFile);
    }

    /**
     * Test ZIP detection
     */
    public function test_detects_zip_files(): void
    {
        $testFile = $this->createTestFile("\x50\x4B\x03\x04");
        $mimeType = $this->detector->detect($testFile);

        $this->assertEquals('application/zip', $mimeType);

        unlink($testFile);
    }

    /**
     * Test PHP file detection (dangerous)
     */
    public function test_detects_php_files(): void
    {
        $testFile = $this->createTestFile("<?php");
        $mimeType = $this->detector->detect($testFile);

        $this->assertEquals('application/x-php', $mimeType);
        $this->assertTrue($this->detector->isDangerous($mimeType));

        unlink($testFile);
    }

    /**
     * Test Windows executable detection
     */
    public function test_detects_windows_executables(): void
    {
        $testFile = $this->createTestFile("\x4D\x5A");
        $mimeType = $this->detector->detect($testFile);

        $this->assertEquals('application/x-msdownload', $mimeType);
        $this->assertTrue($this->detector->isDangerous($mimeType));

        unlink($testFile);
    }

    /**
     * Test shell script detection
     */
    public function test_detects_shell_scripts(): void
    {
        $testFile = $this->createTestFile("#!/bin/bash");
        $mimeType = $this->detector->detect($testFile);

        $this->assertEquals('text/x-shellscript', $mimeType);
        $this->assertTrue($this->detector->isDangerous($mimeType));

        unlink($testFile);
    }

    /**
     * Test dangerous file type identification
     */
    public function test_identifies_dangerous_files(): void
    {
        $this->assertTrue($this->detector->isDangerous('application/x-php'));
        $this->assertTrue($this->detector->isDangerous('application/x-executable'));
        $this->assertTrue($this->detector->isDangerous('text/x-shellscript'));

        $this->assertFalse($this->detector->isDangerous('image/jpeg'));
        $this->assertFalse($this->detector->isDangerous('application/pdf'));
    }

    /**
     * Test handling of non-existent files
     */
    public function test_returns_null_for_non_existent_file(): void
    {
        $mimeType = $this->detector->detect('/path/to/non/existent/file.jpg');

        $this->assertNull($mimeType);
    }

    /**
     * Helper method to create a test file with specific magic bytes
     */
    protected function createTestFile(string $content): string
    {
        $tempFile = tempnam(sys_get_temp_dir(), 'safeguard_test_');
        file_put_contents($tempFile, $content . str_repeat("\x00", 100));

        return $tempFile;
    }
}
