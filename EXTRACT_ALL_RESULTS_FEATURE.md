# Extract All Results Feature

This document describes the new "Extract All Results" feature that allows webscan to return all extracted results from Nuclei templates, even when matchers don't match.

## Problem

By default, Nuclei (and webscan) only returns results when both extractors have extracted data AND matchers have matched. This means that if a template has extractors that successfully extract data but the matchers don't match, those extracted results are discarded.

For example:
- Template extracts version information from a response
- Template has a matcher that checks for a vulnerability condition  
- If the vulnerability condition isn't met, the version information is lost
- User wants to see the version information regardless of whether it's vulnerable

## Solution

The Extract All Results feature modifies the Nuclei engine behavior to return all extracted results, regardless of matcher status.

## Implementation

The feature has been implemented with three ways to enable it:

### 1. Environment Variable (Available Now)
```bash
export WEBSCAN_EXTRACT_ALL_RESULTS=true
webscan pentest application dast --targets https://example.com
```

### 2. Command Line Flag (Available Now)
```bash
webscan --extract-all-results pentest application dast --targets https://example.com
```

### 3. API Configuration (Future - requires Fern code generation)
```yaml
nucleiConfig:
  extractAllResults: true
```

## Technical Details

The implementation works by:

1. **Configuration**: When `extractAllResults` is enabled, the Nuclei engine is configured with `MatcherStatus = true`
2. **Engine Behavior**: This forces Nuclei to report results even when matchers don't match
3. **Result Processing**: All extracted results are included in the ExtractedResults field of the output

### Code Changes Made

1. **Runner Configuration** (`utils/nuclei/runner/runner.go`):
   - Added `ExtractAllResults` field to Config struct
   - Modified `buildNucleiOptions` to check environment variable and flag
   - Set `MatcherStatus = true` when extract-all-results mode is enabled

2. **Command Line Interface** (`cmd/root.go`, `internal/config/config.go`):
   - Added `--extract-all-results` flag to root command
   - Added ExtractAllResults field to RootFlags struct

3. **API Schema** (`fern/definition/common/nuclei/config.yml`):
   - Added optional `extractAllResults` boolean field to NucleiConfig

## Usage Examples

### Environment Variable Method
```bash
# Enable extract-all-results mode globally
export WEBSCAN_EXTRACT_ALL_RESULTS=true

# Run a pentest scan - will now return all extracted data
webscan pentest application dast --targets https://httpbin.org

# Run enumeration - will now capture all discovered data
webscan enumerate cms wordpress --target https://wordpress-site.com
```

### Command Line Flag Method  
```bash
# Enable for a specific command
webscan --extract-all-results pentest application cve --targets https://target.com

# Works with any webscan command that uses Nuclei
webscan --extract-all-results enumerate general rate-limit --target https://api.example.com
```

## Expected Behavior Changes

When Extract All Results is enabled:

1. **More Results**: Templates that previously returned no results due to failed matchers will now return extracted data
2. **Version Information**: Extractors that capture version info will always return data
3. **Technology Detection**: Templates that identify technologies but don't find vulnerabilities will still return identification data
4. **Debug Information**: More detailed information about what was found during scanning

## Use Cases

- **Asset Inventory**: Collect all version information and technology identifiers
- **Reconnaissance**: Gather maximum information during initial scanning phases  
- **Compliance**: Document all discovered technologies and versions
- **Research**: Analyze extracted data patterns without vulnerability filtering

## Performance Considerations

Enabling this feature may:
- Increase the volume of results returned
- Slightly impact performance due to additional result processing
- Generate more comprehensive but potentially noisier output

## Status

- ✅ Environment variable support implemented
- ✅ Command line flag support implemented  
- ✅ Core engine modification implemented
- ⏳ API configuration support (pending Fern code generation)
- ⏳ Full integration testing (pending dependency resolution)

## Future Enhancements

1. **Selective Extraction**: Allow enabling extract-all-results for specific template categories
2. **Result Filtering**: Post-processing filters to manage increased result volume  
3. **Template Configuration**: Per-template override settings