# Discover

The `webscan discover` command performs scanning tasks that locate web applications and collect information about pages and routes.

## Usage

```bash
webscan discover [command]
```

## Commands

### Application

Identify technologies running on a set of targets.

#### Usage
```bash
webscan discover application --resource-type API_APPLICATION --modules GRAPHQL --targets https://example.com
```

#### Help Text
```bash
webscan discover application -h
Perform application fingerprinting to identify web technologies.

Usage:
  webscan discover application [flags]

Flags:
      --fingerprint-file string   Path to the fingerprint definitions file (default "configs/discover/application/fingerprints.json")
  -h, --help                      help for application
      --modules strings           Specific fingerprinting modules to run
      --resource-type string      Type of resource to fingerprint (e.g., web, api, cms)
      --targets strings           URL targets to perform fingerprinting against
      --verify-tls                Verify TLS certificates when making HTTPS requests (default true)
      --timeout int               Timeout per request in seconds (default 30)

Global Flags:
  -o, --output string        Output format (signal, json, yaml). Default value is signal (default "signal")
  -f, --output-file string   Path to output file. If blank, will output to STDOUT
  -q, --quiet                Suppress output
  -v, --verbose              Verbose output
```

### Page

Capture and analyze individual pages.

#### Usage
```bash
webscan discover page --target https://example.com --screenshot
```

#### Help Text
```bash
webscan discover page -h
Capture and analyze web pages to extract content and screenshots.

Usage:
  webscan discover page [flags]

Flags:
      --browserbase-countries strings   List of countries to use for Browserbase proxy
      --browserbase-project string      Browserbase project ID
      --browserbase-proxy               Use Browserbase proxy for requests
      --browserbase-token string        Browserbase API token for cloud browser access
      --headless-path string            Path to headless browser executable
  -h, --help                            help for page
      --max-redirects int               Maximum number of redirects to follow (default 10)
      --min-dom-stabalize-time int      Minimum time to wait for DOM stabilization in seconds (default 5)
      --request-method string           Request method to use (standard, headless, browserbase) (default "STANDARD")
      --screenshot                      Capture a screenshot of the page
      --target string                   URL target to capture and analyze
      --threads int                     Number of threads to use during capture (default is number of CPUs)
      --timeout int                     Timeout per request in seconds (default 30)
      --verify-tls                      Verify TLS certificates when making HTTPS requests (default true)

Global Flags:
  -o, --output string        Output format (signal, json, yaml). Default value is signal (default "signal")
  -f, --output-file string   Path to output file. If blank, will output to STDOUT
  -q, --quiet                Suppress output
  -v, --verbose              Verbose output
```

### Probe

Determine if targets run web applications.

#### Usage
```bash
webscan discover probe --targets https://example.com
```

#### Help Text
```bash
webscan discover probe -h
Probe targets for web application existence.

Usage:
  webscan discover probe [flags]

Flags:
      --browserbase-countries strings   List of countries to use for Browserbase proxy
      --browserbase-project string      Browserbase project ID
      --browserbase-proxy               Use Browserbase proxy for requests
      --browserbase-token string        Browserbase API token for cloud browser access
      --headless-path string            Path to headless browser executable
      --https-only                      Only probe HTTPS URLs (default true)
  -h, --help                            help for probe
      --max-redirects int               Maximum number of redirects to follow (default 10)
      --min-dom-stabalize-time int      Minimum time to wait for DOM stabilization in seconds (default 5)
      --request-method string           Request method to use (standard, headless, browserbase) (default "STANDARD")
      --targets strings                 URL targets to probe for web applications
      --threads int                     Number of threads to use during probing (default is number of CPUs)
      --timeout int                     Timeout per request in seconds (default 30)
      --verify-tls                      Verify TLS certificates when making HTTPS requests (default true)

Global Flags:
  -o, --output string        Output format (signal, json, yaml). Default value is signal (default "signal")
  -f, --output-file string   Path to output file. If blank, will output to STDOUT
  -q, --quiet                Suppress output
  -v, --verbose              Verbose output
```

### Route

Discover and analyze application routes.

#### Usage
```bash
webscan discover route --target https://example.com
```

#### Help Text
```bash
webscan discover route -h
Discover and analyze web routes to map application structure.

Usage:
  webscan discover route [flags]

Flags:
      --browserbase-countries strings   List of countries to use for Browserbase proxy
      --browserbase-project string      Browserbase project ID
      --browserbase-proxy               Use Browserbase proxy for requests
      --browserbase-token string        Browserbase API token for cloud browser access
      --headless-path string            Path to headless browser executable
  -h, --help                            help for route
      --ignore-static-assets            Exclude static assets from route discovery (default true)
      --max-redirects int               Maximum number of redirects to follow (default 10)
      --min-dom-stabalize-time int      Minimum time to wait for DOM stabilization in seconds (default 5)
      --request-method string           Request method to use (standard, headless, browserbase) (default "STANDARD")
      --require-base-url-match          Only scan routes sharing the target's base URL (default true)
      --spider-depth int                Maximum depth for route spidering (default 1)
      --target string                   URL target to discover routes from
      --threads int                     Number of concurrent threads for scanning
      --timeout int                     Timeout per request in seconds (default 30)
      --verify-tls                      Verify TLS certificates when making HTTPS requests (default true)

Global Flags:
  -o, --output string        Output format (signal, json, yaml). Default value is signal (default "signal")
  -f, --output-file string   Path to output file. If blank, will output to STDOUT
  -q, --quiet                Suppress output
  -v, --verbose              Verbose output
```

### SaaS Active

Actively detect SaaS application instances for a list of organizations.

#### Usage
```bash
webscan discover saas active --orgs example
```

#### Help Text
```bash
webscan discover saas active -h
Active detection of SaaS application instances and evaluation of login pages.

Usage:
  webscan discover saas active [flags]

Flags:
      --browserbase-countries strings   List of countries to use for the proxy
      --browserbase-project string      Browserbase project ID
      --browserbase-proxy               Instruct Browserbase to use a proxy
      --browserbase-token string        Browserbase API token
      --headless-path string            Path to a headless browser executable
  -h, --help                            help for active
      --https-only                      Only show successful attempts over HTTPS (default true)
      --max-redirects int               Maximum number of redirects to follow (default 10)
      --min-dom-stabalize-time int      Minimum time in seconds to wait for DOM to stabilize (default 5)
      --orgs strings                    The organization names to use for discovery
      --request-method string           Request method (headless, browserbase) (default "HEADLESS")
      --saas-companies strings          The specific SaaS companies to use for discovery (Must be present in the SaaS fingerprints file)
      --saas-file-paths strings         Files containing SaaS application fingerprints (default ["configs/discover/saas/active/saas_fingerprints.json"]) 
      --sso-companies strings           The specific SSO companies to use for discovery (Must be present in the SSO fingerprints file)
      --sso-file-paths strings          Files containing SSO application fingerprints (default ["configs/discover/saas/active/sso_fingerprints.json"]) 
      --timeout int                     Timeout in seconds for the capture (default 30)
      --verify-tls                      Verify TLS certificates when making HTTPS requests (default true)

Global Flags:
  -o, --output string        Output format (signal, json, yaml). Default value is signal (default "signal")
  -f, --output-file string   Path to output file. If blank, will output to STDOUT
  -q, --quiet                Suppress output
  -v, --verbose              Verbose output
```

