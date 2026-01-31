<?php
require_once 'vendor/autoload.php';

use Abdian\LaravelSafeguard\MimeTypeDetector;
use Abdian\LaravelSafeguard\PdfScanner;

echo "================================================================\n";
echo "  COMPREHENSIVE TEST SUITE - Laravel Safeguard Bug Fixes\n";
echo "================================================================\n\n";

$passed = 0;
$failed = 0;
$tests = [];

function test($name, $condition, $details = '') {
    global $passed, $failed, $tests;
    if ($condition) {
        $passed++;
        $tests[] = ['name' => $name, 'status' => 'PASS', 'details' => $details];
        echo "  ✓ $name\n";
    } else {
        $failed++;
        $tests[] = ['name' => $name, 'status' => 'FAIL', 'details' => $details];
        echo "  ✗ $name\n";
        if ($details) echo "    Details: $details\n";
    }
}

$detector = new MimeTypeDetector();
$scanner = new PdfScanner();

// ============================================================
// SECTION 1: DOCX/XLSX/PPTX Detection Tests
// ============================================================
echo "--- SECTION 1: Office Open XML Detection ---\n\n";

// Test 1.1: Standard DOCX with [Content_Types].xml
$zip = new ZipArchive();
$docxPath = sys_get_temp_dir() . '/test_' . uniqid() . '.docx';
$zip->open($docxPath, ZipArchive::CREATE);
$zip->addFromString('[Content_Types].xml', '<?xml version="1.0"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/></Types>');
$zip->addFromString('word/document.xml', '<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body><w:p><w:r><w:t>Test</w:t></w:r></w:p></w:body></w:document>');
$zip->addFromString('_rels/.rels', '<?xml version="1.0"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"></Relationships>');
$zip->close();
$mime = $detector->detect($docxPath);
test('DOCX with Content_Types.xml', $mime === 'application/vnd.openxmlformats-officedocument.wordprocessingml.document', "Got: $mime");
unlink($docxPath);

// Test 1.2: DOCX with only word/ directory (no Content_Types check)
$docxPath2 = sys_get_temp_dir() . '/test_' . uniqid() . '.docx';
$zip->open($docxPath2, ZipArchive::CREATE);
$zip->addFromString('word/document.xml', '<document>test</document>');
$zip->addFromString('word/styles.xml', '<styles/>');
$zip->close();
$mime = $detector->detect($docxPath2);
test('DOCX with word/ directory only', $mime === 'application/vnd.openxmlformats-officedocument.wordprocessingml.document', "Got: $mime");
unlink($docxPath2);

// Test 1.3: XLSX Detection
$xlsxPath = sys_get_temp_dir() . '/test_' . uniqid() . '.xlsx';
$zip->open($xlsxPath, ZipArchive::CREATE);
$zip->addFromString('[Content_Types].xml', '<?xml version="1.0"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/></Types>');
$zip->addFromString('xl/workbook.xml', '<workbook/>');
$zip->close();
$mime = $detector->detect($xlsxPath);
test('XLSX Detection', $mime === 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet', "Got: $mime");
unlink($xlsxPath);

// Test 1.4: PPTX Detection
$pptxPath = sys_get_temp_dir() . '/test_' . uniqid() . '.pptx';
$zip->open($pptxPath, ZipArchive::CREATE);
$zip->addFromString('[Content_Types].xml', '<?xml version="1.0"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Override PartName="/ppt/presentation.xml" ContentType="application/vnd.openxmlformats-officedocument.presentationml.presentation.main+xml"/></Types>');
$zip->addFromString('ppt/presentation.xml', '<presentation/>');
$zip->close();
$mime = $detector->detect($pptxPath);
test('PPTX Detection', $mime === 'application/vnd.openxmlformats-officedocument.presentationml.presentation', "Got: $mime");
unlink($pptxPath);

// Test 1.5: Regular ZIP should stay as ZIP
$zipPath = sys_get_temp_dir() . '/test_' . uniqid() . '.zip';
$zip->open($zipPath, ZipArchive::CREATE);
$zip->addFromString('file1.txt', 'Hello');
$zip->addFromString('file2.txt', 'World');
$zip->close();
$mime = $detector->detect($zipPath);
test('Regular ZIP stays as ZIP', $mime === 'application/zip', "Got: $mime");
unlink($zipPath);

// Test 1.6: DOCX with large content (word/ directory might not be in first 512 bytes)
$docxLarge = sys_get_temp_dir() . '/test_large_' . uniqid() . '.docx';
$zip->open($docxLarge, ZipArchive::CREATE);
// Add many files before word/ to push it past 512 bytes
for ($i = 0; $i < 50; $i++) {
    $zip->addFromString("padding/file$i.xml", str_repeat('X', 100));
}
$zip->addFromString('[Content_Types].xml', '<?xml version="1.0"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/></Types>');
$zip->addFromString('word/document.xml', '<document>Large test</document>');
$zip->close();
$mime = $detector->detect($docxLarge);
test('Large DOCX (word/ past 512 bytes)', $mime === 'application/vnd.openxmlformats-officedocument.wordprocessingml.document', "Got: $mime");
unlink($docxLarge);

echo "\n";

// ============================================================
// SECTION 2: PDF Link Detection Tests
// ============================================================
echo "--- SECTION 2: PDF Link Detection ---\n\n";

// Test 2.1: PDF with HTTP link (should be SAFE)
$pdfHttp = sys_get_temp_dir() . '/test_' . uniqid() . '.pdf';
file_put_contents($pdfHttp, "%PDF-1.4
1 0 obj << /Type /Catalog /Pages 2 0 R >> endobj
2 0 obj << /Type /Pages /Kids [3 0 R] /Count 1 >> endobj
3 0 obj << /Type /Page /Parent 2 0 R /Annots [4 0 R] >> endobj
4 0 obj << /Type /Annot /Subtype /Link /A << /S /URI /URI (https://google.com) >> >> endobj
trailer << /Root 1 0 R >>
%%EOF");
$result = $scanner->scan($pdfHttp);
test('PDF with https:// link is SAFE', $result['safe'] === true, "Threats: " . implode(', ', $result['threats']));
test('PDF with https:// has_external_links=true', $result['has_external_links'] === true);
unlink($pdfHttp);

// Test 2.2: PDF with multiple HTTP links
$pdfMulti = sys_get_temp_dir() . '/test_' . uniqid() . '.pdf';
file_put_contents($pdfMulti, "%PDF-1.4
1 0 obj << /Type /Catalog /Pages 2 0 R >> endobj
2 0 obj << /Type /Pages /Kids [3 0 R] /Count 1 >> endobj
3 0 obj << /Type /Page /Parent 2 0 R /Annots [4 0 R 5 0 R 6 0 R] >> endobj
4 0 obj << /Type /Annot /Subtype /Link /A << /S /URI /URI (https://example1.com) >> >> endobj
5 0 obj << /Type /Annot /Subtype /Link /A << /S /URI /URI (http://example2.com) >> >> endobj
6 0 obj << /Type /Annot /Subtype /Link /A << /S /URI /URI (https://example3.com/path?query=1) >> >> endobj
trailer << /Root 1 0 R >>
%%EOF");
$result = $scanner->scan($pdfMulti);
test('PDF with multiple HTTP links is SAFE', $result['safe'] === true);
unlink($pdfMulti);

// Test 2.3: PDF with javascript: protocol (should be UNSAFE)
$pdfJs = sys_get_temp_dir() . '/test_' . uniqid() . '.pdf';
file_put_contents($pdfJs, "%PDF-1.4
1 0 obj << /Type /Catalog /Pages 2 0 R >> endobj
2 0 obj << /Type /Pages /Kids [3 0 R] /Count 1 >> endobj
3 0 obj << /Type /Page /Parent 2 0 R /Annots [4 0 R] >> endobj
4 0 obj << /Type /Annot /Subtype /Link /A << /S /URI /URI (javascript:alert(1)) >> >> endobj
trailer << /Root 1 0 R >>
%%EOF");
$result = $scanner->scan($pdfJs);
test('PDF with javascript: is UNSAFE', $result['safe'] === false, "Threats: " . implode(', ', $result['threats']));
unlink($pdfJs);

// Test 2.4: PDF with file:// protocol (should be UNSAFE)
$pdfFile = sys_get_temp_dir() . '/test_' . uniqid() . '.pdf';
file_put_contents($pdfFile, "%PDF-1.4
1 0 obj << /Type /Catalog /Pages 2 0 R >> endobj
2 0 obj << /Type /Pages /Kids [3 0 R] /Count 1 >> endobj
3 0 obj << /Type /Page /Parent 2 0 R /Annots [4 0 R] >> endobj
4 0 obj << /Type /Annot /Subtype /Link /A << /S /URI /URI (file:///etc/passwd) >> >> endobj
trailer << /Root 1 0 R >>
%%EOF");
$result = $scanner->scan($pdfFile);
test('PDF with file:// is UNSAFE', $result['safe'] === false);
unlink($pdfFile);

// Test 2.5: PDF with data: protocol (should be UNSAFE)
$pdfData = sys_get_temp_dir() . '/test_' . uniqid() . '.pdf';
file_put_contents($pdfData, "%PDF-1.4
1 0 obj << /Type /Catalog /Pages 2 0 R >> endobj
2 0 obj << /Type /Pages >> endobj
/URI (data:text/html,<script>alert(1)</script>)
trailer << /Root 1 0 R >>
%%EOF");
$result = $scanner->scan($pdfData);
test('PDF with data: is UNSAFE', $result['safe'] === false);
unlink($pdfData);

// Test 2.6: PDF with vbscript: protocol (should be UNSAFE)
$pdfVbs = sys_get_temp_dir() . '/test_' . uniqid() . '.pdf';
file_put_contents($pdfVbs, "%PDF-1.4
1 0 obj << /Type /Catalog >> endobj
/URI (vbscript:msgbox)
trailer << /Root 1 0 R >>
%%EOF");
$result = $scanner->scan($pdfVbs);
test('PDF with vbscript: is UNSAFE', $result['safe'] === false);
unlink($pdfVbs);

// Test 2.7: PDF with /JavaScript action (should be UNSAFE)
$pdfJsAction = sys_get_temp_dir() . '/test_' . uniqid() . '.pdf';
file_put_contents($pdfJsAction, "%PDF-1.4
1 0 obj << /Type /Catalog /OpenAction 2 0 R >> endobj
2 0 obj << /S /JavaScript /JS (app.alert('test');) >> endobj
trailer << /Root 1 0 R >>
%%EOF");
$result = $scanner->scan($pdfJsAction);
test('PDF with /JavaScript action is UNSAFE', $result['safe'] === false);
test('PDF with /JavaScript has_javascript=true', $result['has_javascript'] === true);
unlink($pdfJsAction);

// Test 2.8: PDF with /Launch action (should be UNSAFE)
$pdfLaunch = sys_get_temp_dir() . '/test_' . uniqid() . '.pdf';
file_put_contents($pdfLaunch, "%PDF-1.4
1 0 obj << /Type /Catalog /OpenAction 2 0 R >> endobj
2 0 obj << /S /Launch /F (calc.exe) >> endobj
trailer << /Root 1 0 R >>
%%EOF");
$result = $scanner->scan($pdfLaunch);
test('PDF with /Launch action is UNSAFE', $result['safe'] === false);
unlink($pdfLaunch);

// Test 2.9: Clean PDF (no links, no JS) should be SAFE
$pdfClean = sys_get_temp_dir() . '/test_' . uniqid() . '.pdf';
file_put_contents($pdfClean, "%PDF-1.4
1 0 obj << /Type /Catalog /Pages 2 0 R >> endobj
2 0 obj << /Type /Pages /Kids [3 0 R] /Count 1 >> endobj
3 0 obj << /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] >> endobj
trailer << /Root 1 0 R >>
%%EOF");
$result = $scanner->scan($pdfClean);
test('Clean PDF is SAFE', $result['safe'] === true);
test('Clean PDF has_external_links=false', $result['has_external_links'] === false);
test('Clean PDF has_javascript=false', $result['has_javascript'] === false);
unlink($pdfClean);

echo "\n";

// ============================================================
// SECTION 3: Edge Cases
// ============================================================
echo "--- SECTION 3: Edge Cases ---\n\n";

// Test 3.1: Mixed content - HTTP link AND safe content
$pdfMixed = sys_get_temp_dir() . '/test_' . uniqid() . '.pdf';
file_put_contents($pdfMixed, "%PDF-1.4
1 0 obj << /Type /Catalog /Pages 2 0 R >> endobj
2 0 obj << /Type /Pages /Kids [3 0 R] /Count 1 >> endobj
3 0 obj << /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Annots [4 0 R] >> endobj
4 0 obj << /Type /Annot /Subtype /Link /Rect [100 700 200 720] /A << /S /URI /URI (https://safe-link.com) >> >> endobj
trailer << /Root 1 0 R >>
%%EOF");
$result = $scanner->scan($pdfMixed);
test('PDF with only HTTP links (no threats) is SAFE', $result['safe'] === true && $result['has_external_links'] === true);
unlink($pdfMixed);

// Test 3.2: PDF with embedded file (should be UNSAFE)
$pdfEmbed = sys_get_temp_dir() . '/test_' . uniqid() . '.pdf';
file_put_contents($pdfEmbed, "%PDF-1.4
1 0 obj << /Type /Catalog >> endobj
/Type /EmbeddedFile
trailer << /Root 1 0 R >>
%%EOF");
$result = $scanner->scan($pdfEmbed);
test('PDF with /EmbeddedFile is UNSAFE', $result['safe'] === false);
unlink($pdfEmbed);

// Test 3.3: Corrupted/Invalid file
$invalidPath = sys_get_temp_dir() . '/test_' . uniqid() . '.pdf';
file_put_contents($invalidPath, "This is not a PDF file");
$result = $scanner->scan($invalidPath);
test('Invalid PDF is detected', $result['safe'] === false && in_array('Not a valid PDF file', $result['threats']));
unlink($invalidPath);

// Test 3.4: Non-existent file
$result = $scanner->scan('/path/to/nonexistent/file.pdf');
test('Non-existent file handled gracefully', $result['safe'] === false);

// Test 3.5: isBinaryFile for DOCX
$docxBinary = sys_get_temp_dir() . '/test_' . uniqid() . '.docx';
$zip->open($docxBinary, ZipArchive::CREATE);
$zip->addFromString('[Content_Types].xml', '<?xml version="1.0"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/></Types>');
$zip->addFromString('word/document.xml', '<document/>');
$zip->close();
test('DOCX is detected as binary file', $detector->isBinaryFile($docxBinary) === true);
unlink($docxBinary);

echo "\n";

// ============================================================
// SUMMARY
// ============================================================
echo "================================================================\n";
echo "  SUMMARY\n";
echo "================================================================\n\n";

$total = $passed + $failed;
$percentage = round(($passed / $total) * 100, 1);

echo "  Total Tests: $total\n";
echo "  Passed: $passed\n";
echo "  Failed: $failed\n";
echo "  Success Rate: $percentage%\n\n";

if ($failed > 0) {
    echo "  FAILED TESTS:\n";
    foreach ($tests as $t) {
        if ($t['status'] === 'FAIL') {
            echo "    - {$t['name']}\n";
            if ($t['details']) echo "      ({$t['details']})\n";
        }
    }
}

echo "\n================================================================\n";
if ($failed === 0) {
    echo "  ✓ ALL TESTS PASSED!\n";
} else {
    echo "  ✗ SOME TESTS FAILED!\n";
}
echo "================================================================\n";
