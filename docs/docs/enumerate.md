# Enumerate

The `webscan enumerate` command discovers APIs, CMS components, web servers and other application details.

## Usage
```bash
webscan enumerate [command]
```

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
Enumerate GraphQL endpoints.

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
Enumerate Swagger/OpenAPI documentation.

Usage:
  webscan enumerate api-application swagger [flags]

Flags:
  -h, --help            help for swagger
      --target string   URL target to perform Swagger enumeration against
      --timeout int     Timeout per request in seconds (default 30)

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
Enumerate Kubernetes resources.

Usage:
  webscan enumerate kube [flags]

Flags:
  -h, --help            help for kube
      --target string   URL target to perform Kubernetes enumeration against
      --verify-tls      Verify TLS certificates when making HTTPS requests (default true)
      --timeout int     Timeout per request in seconds (default 30)

Global Flags:
  -o, --output string        Output format (signal, json, yaml). Default value is signal (default "signal")
  -f, --output-file string   Path to output file. If blank, will output to STDOUT
  -q, --quiet                Suppress output
  -v, --verbose              Verbose output
```

### CMS WordPress Plugins
```bash
webscan enumerate cms wordpress plugins --targets https://example.com
```
#### Help Text
```bash
webscan enumerate cms wordpress plugins -h
Attempt to enumerate WordPress plugins on a target.

Usage:
  webscan enumerate cms wordpress plugins [flags]

Flags:
      --plugins strings            Specific WordPress plugins to check for
      --plugins-file-paths strings Paths to files containing WordPress plugin lists (default ["configs/enumerate/cms/wordpress/plugins_small.txt"])
  -h, --help                       help for plugins
      --targets strings            URL targets to perform WordPress plugin enumeration against
      --timeout int                Timeout per request in seconds (default 30)
      --threads int                Number of concurrent threads for scanning
      --verify-tls                 Verify TLS certificates when making HTTPS requests (default true)

Global Flags:
  -o, --output string        Output format (signal, json, yaml). Default value is signal (default "signal")
  -f, --output-file string   Path to output file. If blank, will output to STDOUT
  -q, --quiet                Suppress output
  -v, --verbose              Verbose output
```

### Webserver IIS
```bash
webscan enumerate webserver iis --targets https://example.com
```
#### Help Text
```bash
webscan enumerate webserver iis -h
Enumerate IIS servers.

Usage:
  webscan enumerate webserver iis [flags]

Flags:
  -h, --help            help for iis
      --targets strings   URL targets to perform IIS enumeration against
      --threads int       Number of concurrent threads for scanning
      --timeout int       Timeout per request in seconds (default 30)
      --verify-tls        Verify TLS certificates when making HTTPS requests (default true)

Global Flags:
  -o, --output string        Output format (signal, json, yaml). Default value is signal (default "signal")
  -f, --output-file string   Path to output file. If blank, will output to STDOUT
  -q, --quiet                Suppress output
  -v, --verbose              Verbose output
```

### General Ratelimit
```bash
webscan enumerate general ratelimit --targets https://example.com
```
#### Help Text
```bash
webscan enumerate general ratelimit -h
Analyze and test rate limiting controls.

Usage:
  webscan enumerate general ratelimit [flags]

Flags:
  -h, --help            help for ratelimit
      --max-requests int   Maximum number of requests to send (default 10)
      --targets strings    URL targets to perform rate limit enumeration against
      --timespan int       Time window for rate limit testing in seconds (default 10)
      --timeout int        Timeout per request in seconds (default 30)
      --verify-tls         Verify TLS certificates when making HTTPS requests (default true)

Global Flags:
  -o, --output string        Output format (signal, json, yaml). Default value is signal (default "signal")
  -f, --output-file string   Path to output file. If blank, will output to STDOUT
  -q, --quiet                Suppress output
  -v, --verbose              Verbose output
```

