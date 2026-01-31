# Tasks: Critical Security Enhancements

## 1. XXE Protection in SVG/XML Parsing

- [ ] 1.1 Add XXE protection to `SvgScanner::scan()` method
- [ ] 1.2 Create PHP 8.0+ compatible implementation using LIBXML_NOENT
- [ ] 1.3 Add DTD/entity detection in raw content before parsing
- [ ] 1.4 Write unit tests for XXE attack vectors
- [ ] 1.5 Update documentation with XXE protection details

## 2. Symlink/Hardlink Validation

- [ ] 2.1 Create `ValidatesFileAccess` trait in `src/Concerns/`
- [ ] 2.2 Implement `validateFileAccess()` method with symlink check
- [ ] 2.3 Implement path validation (ensure file in allowed directories)
- [ ] 2.4 Apply trait to all existing scanner classes:
  - [ ] 2.4.1 `SvgScanner`
  - [ ] 2.4.2 `ImageScanner`
  - [ ] 2.4.3 `PdfScanner`
  - [ ] 2.4.4 `PhpCodeScanner`
- [ ] 2.5 Add configuration option `security.allowed_upload_paths`
- [ ] 2.6 Write unit tests for symlink attack scenarios

## 3. Archive Content Scanning

- [ ] 3.1 Create `ArchiveScanner` class in `src/`
- [ ] 3.2 Implement ZIP support using native ZipArchive
- [ ] 3.3 Implement dangerous extension detection
- [ ] 3.4 Implement path traversal detection (`../` patterns)
- [ ] 3.5 Implement compression ratio check (zip bomb detection)
- [ ] 3.6 Implement nested archive scanning with depth limit
- [ ] 3.7 Implement file count limit check
- [ ] 3.8 Implement uncompressed size limit check
- [ ] 3.9 Add optional TAR/GZIP support via PharData
- [ ] 3.10 Add optional RAR support (graceful if extension missing)
- [ ] 3.11 Create `SafeguardArchive` validation rule
- [ ] 3.12 Add `archive_scanning` config section
- [ ] 3.13 Register rule in `SafeguardServiceProvider`
- [ ] 3.14 Write comprehensive unit tests

## 4. Office Document Macro Detection

- [ ] 4.1 Create `OfficeScanner` class in `src/`
- [ ] 4.2 Implement Office Open XML detection (check for ZIP structure)
- [ ] 4.3 Implement `vbaProject.bin` file detection
- [ ] 4.4 Implement `[Content_Types].xml` parsing for macro indicators
- [ ] 4.5 Detect macro-enabled extensions disguised as regular extensions
- [ ] 4.6 Implement ActiveX control detection (optional)
- [ ] 4.7 Create `SafeguardOffice` validation rule
- [ ] 4.8 Add `office_scanning` config section
- [ ] 4.9 Register rule in `SafeguardServiceProvider`
- [ ] 4.10 Write unit tests with sample macro-enabled documents

## 5. Integration and Testing

- [ ] 5.1 Update `Safeguard` main rule to include new scanners
- [ ] 5.2 Add new scanners to fluent API:
  - [ ] 5.2.1 `->scanArchives()` method
  - [ ] 5.2.2 `->blockMacros()` method
- [ ] 5.3 Update SecurityLogger with new event types:
  - [ ] 5.3.1 `XXE_DETECTED`
  - [ ] 5.3.2 `ARCHIVE_THREAT`
  - [ ] 5.3.3 `MACRO_DETECTED`
  - [ ] 5.3.4 `SYMLINK_DETECTED`
  - [ ] 5.3.5 `ZIPBOMB_DETECTED`
- [ ] 5.4 Create integration tests
- [ ] 5.5 Create security-focused test suite with attack samples
- [ ] 5.6 Update README with new features
- [ ] 5.7 Update VitePress documentation

## 6. Configuration

- [ ] 6.1 Add `archive_scanning` section to config:
  ```php
  'archive_scanning' => [
      'enabled' => false,
      'max_compression_ratio' => 100,
      'max_uncompressed_size' => 500 * 1024 * 1024,
      'max_files_count' => 10000,
      'max_nesting_depth' => 3,
      'blocked_extensions' => ['php', 'phar', 'exe', 'bat', 'sh', 'cmd', 'ps1'],
  ]
  ```
- [ ] 6.2 Add `office_scanning` section to config:
  ```php
  'office_scanning' => [
      'enabled' => true,
      'block_macros' => true,
      'block_activex' => true,
      'allowed_macro_extensions' => ['docm', 'xlsm', 'pptm'],
  ]
  ```
- [ ] 6.3 Add `security` section to config:
  ```php
  'security' => [
      'check_symlinks' => true,
      'allowed_upload_paths' => null, // null = auto-detect
  ]
  ```

## Dependencies

```
Task 2 (Symlink) blocks Task 3 and 4 (new scanners should use trait)
Task 3.5 (Zip bomb) is part of Task 3 (Archive) but can be developed in parallel
Task 5 depends on Tasks 1-4 completion
Task 6 can be done in parallel with Tasks 1-4
```

## Verification Checklist

- [ ] All unit tests pass
- [ ] PHPStan level 8 passes (if configured)
- [ ] No breaking changes to existing API
- [ ] Documentation updated
- [ ] Config published correctly
- [ ] Security tests cover attack vectors from fixes.md
