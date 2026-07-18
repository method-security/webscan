# Enumerate

The `webscan enumerate` command performs various enumeration scans to identify and analyze web application components, APIs, and security controls.

## Usage
```bash
webscan enumerate [command]
```

## Available Commands

- **api-application**: Enumerate API applications including GraphQL and Swagger endpoints
- **cms**: Enumerate content management systems like WordPress plugins and Drupal modules
- **container-registry**: Enumerate container registries including Docker registries
- **general**: Perform general enumeration tasks like rate limit testing
- **kube**: Enumerate Kubernetes resources and configurations

## Commands

### API Application

Subcommands for enumerating API applications.

#### GraphQL
```bash
webscan enumerate api-application graphql --target https://example.com
```
##### Help Text
```bash
webscan enumerate api-application graphql -h
Discover and analyze GraphQL endpoints, including introspection queries and potential security issues.

Usage:
  webscan enumerate api-application graphql [flags]

Flags:
  -h, --help            help for graphql
      --target string   URL target to perform GraphQL enumeration against

Global Flags:
  -o, --output string        Output format (signal, json, yaml). Default value is signal (default "signal")
  -f, --output-file string   Path to output file. If blank, will output to STDOUT
  -q, --quiet                Suppress output
  -v, --verbose              Verbose output
```

#### Swagger
```bash
webscan enumerate api-application swagger --target https://example.com
```
##### Help Text
```bash
webscan enumerate api-application swagger -h
Discover and analyze Swagger/OpenAPI documentation to identify API endpoints and their specifications.

Usage:
  webscan enumerate api-application swagger [flags]

Flags:
      --headless-path string   Path to headless browser executable
  -h, --help                   help for swagger
      --target string          URL target to perform Swagger enumeration against
      --timeout int            Timeout per request in seconds (default 30)

Global Flags:
  -o, --output string        Output format (signal, json, yaml). Default value is signal (default "signal")
  -f, --output-file string   Path to output file. If blank, will output to STDOUT
  -q, --quiet                Suppress output
  -v, --verbose              Verbose output
```

### Kube
```bash
webscan enumerate kube --target https://example.com
```
#### Help Text
```bash
webscan enumerate kube -h
Discover and analyze Kubernetes resources, including pods, services, and potential security misconfigurations.

Usage:
  webscan enumerate kube [flags]

Flags:
  -h, --help            help for kube
      --target string   URL target to perform Kubernetes enumeration against
      --timeout int     Timeout per request in seconds (default 30)
      --verify-tls      Verify TLS certificates when making HTTPS requests

Global Flags:
  -o, --output string        Output format (signal, json, yaml). Default value is signal (default "signal")
  -f, --output-file string   Path to output file. If blank, will output to STDOUT
  -q, --quiet                Suppress output
  -v, --verbose              Verbose output
```

### CMS

Enumerate content management systems.

#### WordPress Plugins

In addition to enumerating installed plugins, this command detects the WordPress core version running on the target, trying (in order of reliability) `/readme.html`, the HTML `<meta name="generator">` tag, and `?ver=` query strings on core `wp-includes`/`wp-admin` asset URLs. The detected version and the method that found it are reported as `version` and `versionSource` on each target.

```bash
webscan enumerate cms wordpress plugins --targets https://example.com
```
##### Help Text
```bash
webscan enumerate cms wordpress plugins -h
Discover and analyze WordPress plugins to identify installed components and potential security issues.

Usage:
  webscan enumerate cms wordpress plugins [flags]

Flags:
  -h, --help                         help for plugins
      --jitter int                   Jitter percentage (0-100) to apply random variance to sleep delay
      --plugins strings              Specific WordPress plugins to check for
      --plugins-file-paths strings   Paths to files containing WordPress plugin lists
      --plugins-file-size string     Size of the WordPress plugin list to use (default "SMALL")
      --sleep int                    Number of seconds to sleep between requests
      --targets strings              URL targets to perform WordPress plugin enumeration against
      --threads int                  Number of concurrent threads for scanning (default 50)
      --timeout int                  Timeout per request in seconds (default 30)
      --user-agent string            User-Agent preset (RANDOM, CHROME, FIREFOX, SAFARI, EDGE) (default "RANDOM")
      --verify-tls                   Verify TLS certificates when making HTTPS requests

Global Flags:
      --http-proxy string    HTTP/HTTPS proxy URL (e.g., http://proxy.example.com:8080)
  -o, --output string        Output format (signal, json, yaml). Default value is signal (default "signal")
  -f, --output-file string   Path to output file. If blank, will output to STDOUT
  -q, --quiet                Suppress output
      --socks-proxy string   SOCKS proxy URL (e.g., socks5://proxy.example.com:1080)
  -v, --verbose              Verbose output
```

#### Drupal Modules
```bash
webscan enumerate cms drupal modules --targets https://example.com
```
##### Help Text
```bash
webscan enumerate cms drupal modules -h
Discover and analyze Drupal modules to identify installed components and potential security issues.

Usage:
  webscan enumerate cms drupal modules [flags]

Flags:
  -h, --help                         help for modules
      --modules strings              Specific Drupal modules to check for
      --modules-file-paths strings   Paths to files containing Drupal module lists
      --modules-file-size string     Size of the Drupal module list to use (default "SMALL")
      --targets strings              URL targets to perform Drupal module enumeration against
      --threads int                  Number of concurrent threads for scanning (default 50)
      --timeout int                  Timeout per request in seconds (default 30)
      --verify-tls                   Verify TLS certificates when making HTTPS requests

Global Flags:
  -o, --output string        Output format (signal, json, yaml). Default value is signal (default "signal")
  -f, --output-file string   Path to output file. If blank, will output to STDOUT
  -q, --quiet                Suppress output
  -v, --verbose              Verbose output
```


### Container Registry

Enumerate container registries and their contents.

#### Docker
```bash
webscan enumerate container-registry docker --targets https://registry.example.com
```
##### Help Text
```bash
webscan enumerate container-registry docker -h
Discover and analyze Docker container registries, including repositories, images, and their manifest data.

Usage:
  webscan enumerate container-registry docker [flags]

Flags:
  -h, --help              help for docker
      --targets strings   URLs of Docker Container Registries to enumerate
      --threads int       Number of concurrent manifest requests per repository (default 50)
      --timeout int       Timeout per request in seconds (default 30)
      --verify-tls        Verify TLS certificates when making HTTPS requests

Global Flags:
  -o, --output string        Output format (signal, json, yaml). Default value is signal (default "signal")
  -f, --output-file string   Path to output file. If blank, will output to STDOUT
  -q, --quiet                Suppress output
  -v, --verbose              Verbose output
```

### General

Perform general enumeration tasks.

#### Ratelimit
```bash
webscan enumerate general ratelimit --targets https://example.com
```
##### Help Text
```bash
webscan enumerate general ratelimit -h
Analyze and test rate limiting controls to identify potential bypasses or misconfigurations.

Usage:
  webscan enumerate general ratelimit [flags]

Flags:
  -h, --help                help for ratelimit
      --max-requests int    Maximum number of requests to send (default 100)
      --sleep int           Time window between requests in seconds
      --targets strings     URL targets to perform rate limit enumeration against
      --threads int         Number of concurrent threads for scanning (default 100)
      --timeout int         Timeout per request in seconds (default 5)
      --verify-tls          Verify TLS certificates when making HTTPS requests

Global Flags:
  -o, --output string        Output format (signal, json, yaml). Default value is signal (default "signal")
  -f, --output-file string   Path to output file. If blank, will output to STDOUT
  -q, --quiet                Suppress output
  -v, --verbose              Verbose output
```
