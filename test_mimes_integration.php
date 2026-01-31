<?php
require_once 'vendor/autoload.php';

use Abdian\LaravelSafeguard\ExtensionMimeMap;
use Abdian\LaravelSafeguard\MimeTypeDetector;
use Abdian\LaravelSafeguard\Rules\Safeguard;
use Illuminate\Http\UploadedFile;

echo "================================================================\n";
echo "  Testing: Mimes Rule Integration & Extension-MIME Mapping\n";
echo "================================================================\n\n";

$passed = 0;
$failed = 0;

function test($name, $condition, $details = '') {
    global $passed, $failed;
    if ($condition) {
        $passed++;
        echo "  ✓ $name\n";
    } else {
        $failed++;
        echo "  ✗ $name\n";
        if ($details) echo "    Details: $details\n";
    }
}

// ============================================================
// SECTION 1: ExtensionMimeMap Tests
// ============================================================
echo "--- SECTION 1: ExtensionMimeMap ---\n\n";

// Test 1.1: Basic extension to MIME mapping
$mimes = ExtensionMimeMap::getMimeTypes('jpg');
test('jpg -> image/jpeg', in_array('image/jpeg', $mimes));

$mimes = ExtensionMimeMap::getMimeTypes('png');
test('png -> image/png', in_array('image/png', $mimes));

$mimes = ExtensionMimeMap::getMimeTypes('pdf');
test('pdf -> application/pdf', in_array('application/pdf', $mimes));

$mimes = ExtensionMimeMap::getMimeTypes('docx');
test('docx -> wordprocessingml.document', in_array('application/vnd.openxmlformats-officedocument.wordprocessingml.document', $mimes));

$mimes = ExtensionMimeMap::getMimeTypes('xlsx');
test('xlsx -> spreadsheetml.sheet', in_array('application/vnd.openxmlformats-officedocument.spreadsheetml.sheet', $mimes));

// Test 1.2: Extension with leading dot
$mimes = ExtensionMimeMap::getMimeTypes('.jpg');
test('.jpg (with dot) -> image/jpeg', in_array('image/jpeg', $mimes));

// Test 1.3: Case insensitivity
$mimes = ExtensionMimeMap::getMimeTypes('JPG');
test('JPG (uppercase) -> image/jpeg', in_array('image/jpeg', $mimes));

// Test 1.4: Unknown extension
$mimes = ExtensionMimeMap::getMimeTypes('xyz123');
test('Unknown extension returns empty', empty($mimes));

// Test 1.5: Primary MIME type
$mime = ExtensionMimeMap::getPrimaryMimeType('jpeg');
test('Primary MIME for jpeg', $mime === 'image/jpeg');

// Test 1.6: Extensions to MIME types (bulk conversion)
$mimes = ExtensionMimeMap::extensionsToMimeTypes(['jpg', 'png', 'pdf']);
test('Bulk conversion (jpg,png,pdf)',
    in_array('image/jpeg', $mimes) &&
    in_array('image/png', $mimes) &&
    in_array('application/pdf', $mimes)
);

// Test 1.7: isValidExtensionForMime
test('jpg valid for image/jpeg', ExtensionMimeMap::isValidExtensionForMime('jpg', 'image/jpeg'));
test('jpeg valid for image/jpeg', ExtensionMimeMap::isValidExtensionForMime('jpeg', 'image/jpeg'));
test('png NOT valid for image/jpeg', !ExtensionMimeMap::isValidExtensionForMime('png', 'image/jpeg'));

// Test 1.8: getExtensions (reverse lookup)
$extensions = ExtensionMimeMap::getExtensions('image/jpeg');
test('image/jpeg -> jpg,jpeg', in_array('jpg', $extensions) && in_array('jpeg', $extensions));

// Test 1.9: isKnownExtension
test('jpg is known extension', ExtensionMimeMap::isKnownExtension('jpg'));
test('xyz is NOT known extension', !ExtensionMimeMap::isKnownExtension('xyz'));

echo "\n";

// ============================================================
// SECTION 2: Strict Extension-MIME Matching Tests
// ============================================================
echo "--- SECTION 2: Strict Extension-MIME Matching ---\n\n";

// Create test files with mismatched extensions
$detector = new MimeTypeDetector();

// Test 2.1: JPEG file with .jpg extension (should pass)
$jpegPath = sys_get_temp_dir() . '/test_correct.jpg';
file_put_contents($jpegPath, "\xFF\xD8\xFF\xE0" . str_repeat("\x00", 100)); // JPEG magic bytes
$detectedMime = $detector->detect($jpegPath);
$isValid = ExtensionMimeMap::isValidExtensionForMime('jpg', $detectedMime);
test('JPEG with .jpg extension is valid', $detectedMime === 'image/jpeg' && $isValid);
unlink($jpegPath);

// Test 2.2: JPEG file with .png extension (should fail strict check)
$jpegAsPng = sys_get_temp_dir() . '/test_mismatch.png';
file_put_contents($jpegAsPng, "\xFF\xD8\xFF\xE0" . str_repeat("\x00", 100)); // JPEG magic bytes
$detectedMime = $detector->detect($jpegAsPng);
$isValid = ExtensionMimeMap::isValidExtensionForMime('png', $detectedMime);
test('JPEG with .png extension is INVALID (extension mismatch)', $detectedMime === 'image/jpeg' && !$isValid);
unlink($jpegAsPng);

// Test 2.3: PNG file with correct extension
$pngPath = sys_get_temp_dir() . '/test_correct.png';
file_put_contents($pngPath, "\x89\x50\x4E\x47\x0D\x0A\x1A\x0A" . str_repeat("\x00", 100)); // PNG magic bytes
$detectedMime = $detector->detect($pngPath);
$isValid = ExtensionMimeMap::isValidExtensionForMime('png', $detectedMime);
test('PNG with .png extension is valid', $detectedMime === 'image/png' && $isValid);
unlink($pngPath);

// Test 2.4: PDF file with correct extension
$pdfPath = sys_get_temp_dir() . '/test_correct.pdf';
file_put_contents($pdfPath, "%PDF-1.4\n%%EOF");
$detectedMime = $detector->detect($pdfPath);
$isValid = ExtensionMimeMap::isValidExtensionForMime('pdf', $detectedMime);
test('PDF with .pdf extension is valid', $detectedMime === 'application/pdf' && $isValid);
unlink($pdfPath);

// Test 2.5: PDF file with .jpg extension (should fail strict check)
$pdfAsJpg = sys_get_temp_dir() . '/test_mismatch.jpg';
file_put_contents($pdfAsJpg, "%PDF-1.4\n%%EOF");
$detectedMime = $detector->detect($pdfAsJpg);
$isValid = ExtensionMimeMap::isValidExtensionForMime('jpg', $detectedMime);
test('PDF with .jpg extension is INVALID (extension mismatch)', $detectedMime === 'application/pdf' && !$isValid);
unlink($pdfAsJpg);

echo "\n";

// ============================================================
// SECTION 3: Strict Extension Matching Logic (Unit Tests)
// ============================================================
echo "--- SECTION 3: Strict Extension Matching Logic ---\n\n";

// Test the core logic that will be used by Safeguard rule
// (Testing without full Laravel bootstrap)

// Test 3.1: JPEG file with .jpg extension
$jpegContent = "\xFF\xD8\xFF\xE0" . str_repeat("\x00", 100);
$detectedMime = $detector->detect(createTempFile($jpegContent));
$extension = 'jpg';
$isValid = ExtensionMimeMap::isValidExtensionForMime($extension, $detectedMime);
test('Strict: JPEG content + .jpg extension = VALID', $isValid);

// Test 3.2: JPEG file with .png extension (mismatch)
$isValid = ExtensionMimeMap::isValidExtensionForMime('png', $detectedMime);
test('Strict: JPEG content + .png extension = INVALID', !$isValid);

// Test 3.3: PNG file with .png extension
$pngContent = "\x89\x50\x4E\x47\x0D\x0A\x1A\x0A" . str_repeat("\x00", 100);
$detectedMime = $detector->detect(createTempFile($pngContent));
$isValid = ExtensionMimeMap::isValidExtensionForMime('png', $detectedMime);
test('Strict: PNG content + .png extension = VALID', $isValid);

// Test 3.4: PNG file with .gif extension (mismatch)
$isValid = ExtensionMimeMap::isValidExtensionForMime('gif', $detectedMime);
test('Strict: PNG content + .gif extension = INVALID', !$isValid);

// Test 3.5: PDF file with .pdf extension
$pdfContent = "%PDF-1.4\n%%EOF";
$detectedMime = $detector->detect(createTempFile($pdfContent));
$isValid = ExtensionMimeMap::isValidExtensionForMime('pdf', $detectedMime);
test('Strict: PDF content + .pdf extension = VALID', $isValid);

// Test 3.6: PDF file with .docx extension (mismatch)
$isValid = ExtensionMimeMap::isValidExtensionForMime('docx', $detectedMime);
test('Strict: PDF content + .docx extension = INVALID', !$isValid);

// Helper function
function createTempFile($content) {
    $path = sys_get_temp_dir() . '/mime_test_' . uniqid();
    file_put_contents($path, $content);
    register_shutdown_function(function() use ($path) { @unlink($path); });
    return $path;
}

echo "\n";

// ============================================================
// SECTION 4: Integration scenario (simulating Laravel mimes rule)
// ============================================================
echo "--- SECTION 4: Laravel mimes Rule Integration Scenario ---\n\n";

// Simulate what happens when 'mimes:jpg,png,pdf' is parsed
$extensions = ['jpg', 'png', 'pdf'];
$convertedMimes = ExtensionMimeMap::extensionsToMimeTypes($extensions);

test('mimes:jpg,png,pdf converts correctly',
    in_array('image/jpeg', $convertedMimes) &&
    in_array('image/png', $convertedMimes) &&
    in_array('application/pdf', $convertedMimes),
    'Converted: ' . implode(', ', $convertedMimes)
);

// Test with DOCX
$extensions = ['docx', 'xlsx', 'pptx'];
$convertedMimes = ExtensionMimeMap::extensionsToMimeTypes($extensions);

test('mimes:docx,xlsx,pptx converts to Office MIME types',
    in_array('application/vnd.openxmlformats-officedocument.wordprocessingml.document', $convertedMimes) &&
    in_array('application/vnd.openxmlformats-officedocument.spreadsheetml.sheet', $convertedMimes) &&
    in_array('application/vnd.openxmlformats-officedocument.presentationml.presentation', $convertedMimes)
);

echo "\n";

// ============================================================
// SUMMARY
// ============================================================
echo "================================================================\n";
echo "  SUMMARY\n";
echo "================================================================\n\n";

$total = $passed + $failed;
$percentage = $total > 0 ? round(($passed / $total) * 100, 1) : 0;

echo "  Total Tests: $total\n";
echo "  Passed: $passed\n";
echo "  Failed: $failed\n";
echo "  Success Rate: $percentage%\n\n";

echo "================================================================\n";
if ($failed === 0) {
    echo "  ✓ ALL TESTS PASSED!\n";
} else {
    echo "  ✗ SOME TESTS FAILED!\n";
}
echo "================================================================\n";
