# webscan Project Context

## Overview

webscan is a comprehensive web application security scanning and enumeration tool that provides security teams with data-rich insights into web applications and services. It follows the CLI Development Conventions for attack stage organization and implements discover, enumerate, and pentest capabilities.

## Architecture

The tool follows the standard CLI Development Conventions with clear separation by attack stages:

### Attack Stages

1. **Discover Stage** (`internal/discover/`)
   - Web application discovery and reconnaissance
   - Technology stack fingerprinting
   - Endpoint and directory discovery

2. **Enumerate Stage** (`internal/enumerate/`)
   - Deep web application analysis
   - Parameter discovery and testing
   - Authentication mechanism enumeration

3. **Pentest Stage** (`internal/pentest/`)
   - Active security testing
   - Vulnerability exploitation attempts
   - Authentication bypass testing

### Core Components

1. **Discovery Module** (`internal/discover/`)
   - Web server fingerprinting
   - Directory and file enumeration
   - Technology stack identification
   - SSL/TLS certificate analysis

2. **Enumeration Module** (`internal/enumerate/`)
   - Parameter fuzzing and discovery
   - Form and input field analysis
   - Authentication mechanism testing
   - API endpoint discovery

3. **Penetration Testing Module** (`internal/pentest/`)
   - SQL injection testing
   - Cross-site scripting (XSS) detection
   - Authentication bypass attempts
   - File inclusion vulnerability testing

### CLI Structure (`cmd/`)
- `root.go` - Main CLI setup with Cobra
- `discover.go` - Discovery command implementations
- `enumerate.go` - Enumeration command implementations  
- `pentest.go` - Penetration testing command implementations

### Generated Code (`generated/go/`)
- Fern-generated Go types and clients
- Web scanning definitions and structures
- API interfaces for type safety

### Utilities (`utils/`)
- HTTP client utilities
- URL parsing and validation
- Status code handling
- File management utilities

## Project Structure

- **Language**: Go
- **Module**: github.com/Method-Security/webscan
- **CLI Framework**: Cobra
- **Type Generation**: Fern
- **HTTP Client**: Standard Go HTTP client with custom configurations
- **Testing**: Standard Go testing + web application integration tests

## Key Web Scanning Capabilities

- **Web Server Analysis**: Technology detection, header analysis, SSL/TLS assessment
- **Directory Discovery**: Brute force enumeration, common path testing
- **Parameter Testing**: GET/POST parameter discovery, injection testing
- **Authentication Testing**: Login form analysis, session management testing
- **Vulnerability Detection**: Common web vulnerabilities (OWASP Top 10)
- **API Testing**: REST API endpoint discovery and testing

## Development Patterns

### CLI Development Conventions
- Follow the CLI Development Conventions for attack stage organization
- Use `<stage>Cmd` in camelCase for top-level commands (e.g., `discoverCmd`)
- Use `<stage><Component>Cmd` for subcommands (e.g., `discoverWebCmd`)
- Implement Run functions with action verbs (e.g., `RunWebDiscovery`, `RunDirectoryEnum`)

### Flag Naming and Handling
- Use kebab-case for CLI flags: `--target-url`
- Use camelCase when extracting flags: `targetUrl, err := cmd.Flags().GetString("target-url")`
- Always check errors when extracting flags:
  ```go
  if err != nil {
      a.OutputSignal.AddError(err)
      return
  }
  ```
- Use `.GetStringSlice` for slice inputs with plural flag names
- Mark required flags explicitly: `_ = cmd.MarkFlagRequired("target")`

### Code Organization
- Repository organized by attack stage (`discover`, `enumerate`, `pentest`)
- Mirror naming between `fern/definition/<stage>/<component>.yml`, `internal/<stage>/<component>.go`, and `cmd/<stage>.go`
- Use subdirectories for complex components, flat files for simple ones

### Web Scanning Specific Patterns
- Implement proper HTTP client configuration with timeouts
- Handle different response codes appropriately
- Implement rate limiting to avoid overwhelming targets
- Support custom headers and authentication
- Handle redirects and cookies properly
- Implement proper error handling for network issues

### Error Handling
```go
if err != nil {
    a.OutputSignal.AddError(err)
    return
}
```

### Fern Type Requirements
- **MANDATORY**: Every CLI command with output must have a corresponding Fern report structure
- **Three-Part Structure Pattern**: All commands must define:
  ```yaml
  # 1. Config type for input parameters
  <Stage><Component>Config:
    properties:
      # Web scanning configuration parameters
      targetUrl: string
      timeout: optional<integer>
      headers: optional<map<string, string>>
  
  # 2. Result type for output data
  <Stage><Component>Result:
    properties:
      # Web scanning result data
      pages: optional<list<WebPage>>
      vulnerabilities: optional<list<Vulnerability>>
  
  # 3. Report type wrapping config, result, and errors
  <Stage><Component>Report:
    properties:
      config: <Stage><Component>Config
      result: <Stage><Component>Result
      errors: optional<list<string>>
  ```
- **Web Scanning Example Implementation**:
  ```yaml
  DiscoverWebConfig:
    properties:
      targetUrl: string
      maxDepth: integer
      followRedirects: boolean
  
  DiscoverWebResult:
    properties:
      pages: optional<list<WebPage>>
      technologies: optional<list<Technology>>
  
  DiscoverWebReport:
    properties:
      config: DiscoverWebConfig
      result: DiscoverWebResult
      errors: optional<list<string>>
  ```
- **Web-Specific Types**: Include web scanning specific enums and objects:
  ```yaml
  HttpMethod:
    enum: [GET, POST, PUT, DELETE, PATCH, HEAD, OPTIONS]
  ResponseCode:
    enum: [OK_200, NOT_FOUND_404, SERVER_ERROR_500, ...]
  VulnerabilityType:
    enum: [SQL_INJECTION, XSS, CSRF, DIRECTORY_TRAVERSAL, ...]
  ```
- **Type Organization**: Follow the CLI Development Conventions type ordering:
  1. ENUMs (e.g., `HttpMethod`, `VulnerabilityType`)
  2. Common Objects (e.g., `HttpRequest`, `WebPage`)
  3. Config Types (e.g., `DiscoverWebConfig`)
  4. Result Types (e.g., `DiscoverWebResult`)
  5. Report Types (e.g., `DiscoverWebReport`)

### Output Structure
```go
a.OutputSignal.Content = report
```

## Important Notes

- **Target Consent**: Only scan applications you own or have explicit permission to test
- **Rate Limiting**: Implement appropriate delays to avoid overwhelming target applications
- **Legal Compliance**: Ensure all scanning activities comply with legal requirements and terms of service
- **False Positives**: Implement validation mechanisms to reduce false positive findings
- **Authentication**: Support various authentication mechanisms (basic, session-based, token-based)

## Development Commands

```bash
# MANDATORY: Run after completing TODOs to ensure code can be merged
./godelw verify

# Build the binary
./godelw build
```

## Development Workflow

1. Follow CLI Development Conventions for new commands
2. Use Fern definitions for type safety
3. Implement proper HTTP handling and error management
4. Test with various web application types and configurations
5. Follow existing patterns for consistency
6. **CRITICAL**: Always run `./godelw verify` after TODO completion before merging

## File Structure Conventions

- `/cmd/` - CLI command implementations
- `/internal/<stage>/` - Web scanning capability implementations
- `/fern/definition/` - Fern API definitions
- `/generated/go/` - Generated Go code
- `/configs/` - Configuration files and wordlists
- `/utils/` - HTTP and utility functions
- `/docs/` - Documentation

## Development Practices

- Follow CLI Development Conventions exactly
- Implement comprehensive HTTP error handling
- Respect target application performance and availability
- Handle sensitive data (credentials, session tokens) securely
- Support various web technologies and frameworks
- Always end files with a single newline