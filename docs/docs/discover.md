# Discover

The `webscan discover` command performs scanning tasks that locate web applications and collect information about pages and routes.

## Usage

```bash
webscan discover [command]
```

## Available Commands

- **application**: Perform application fingerprinting and technology detection
- **directory**: Directory and file bruteforce discovery
- **page**: Web page capture and analysis
- **probe**: Probe targets for web application existence
- **route**: Route discovery and analysis
- **saas**: SaaS application discovery by organization name

## Common Flags

The following flag is available on all `discover` subcommands:

- `--ignore-cross-domain-redirects` (bool, default: `true`) — Do not follow redirects to a different domain and treat them as errors

## Commands

### Application

Identify technologies and services running on a set of targets.

#### Usage
```bash
webscan discover application --resource-type ALL --targets https://example.com --threads 10 --verbose-logs
```

#### Help Text
```bash
webscan discover application -h
Perform application fingerprinting to identify web technologies, and services running on target URLs.

Usage:
  webscan discover application [flags]

Flags:
      --global-rate-limit int   Global rate limit in requests per second (default 10)
      --global-timeout int      Maximum total scan time in seconds
  -h, --help                    help for application
      --proxy string            Optional HTTP proxy URL
      --resource-type string    Type of resource to fingerprint (e.g., web, api, cms) (default "ALL")
      --targets strings         URL targets to perform fingerprinting against
      --threads int             Number of concurrent threads for scanning (default 25)
      --timeout int             Timeout per request in seconds (default 30)
      --verbose-logs            Verbose logs

Global Flags:
  -o, --output string        Output format (signal, json, yaml). Default value is signal (default "signal")
  -f, --output-file string   Path to output file. If blank, will output to STDOUT
  -q, --quiet                Suppress output
  -v, --verbose              Verbose output
```

### Directory

Perform directory and file bruteforce discovery.

#### Usage
```bash
webscan discover directory --targets https://example.com --wordlist-type directories --wordlist-size small
```

#### Help Text
```bash
webscan discover directory -h
Perform directory and file bruteforce discovery to identify hidden directories, files, and endpoints on web applications.

Usage:
  webscan discover directory [flags]

Flags:
  -h, --help                                 help for directory
      --http-methods strings                 HTTP methods to use (e.g. GET,POST,PUT) (default [GET])
      --ignore-base-content-match            Ignores valid responses with identical size and word length to the base path, typically signifying a web backend redirect (default true)
      --max-redirects-baseline-request int   Maximum number of redirects to follow for the baseline request (default 10)
      --max-runtime int                      Maximum time to run the engagement in seconds (default 650)
      --paths strings                        Paths to scan
      --response-codes string                Response codes to consider as valid responses (default "200-299")
      --retries int                          Number of times to retry a request if it fails
      --sleep int                            Number of seconds to sleep between requests
      --targets strings                      Targets to be scanned
      --threads int                          Number of threads to use (default 25)
      --threshold float                      Threshold for successful results (default 0.25)
      --timeout int                          Timeout per request in seconds (default 20)
      --verify-tls                           Verify TLS certificates when making HTTPS requests
      --wordlist-size string                 Size of wordlist to use (TINY, SMALL, MEDIUM, LARGE) (default "SMALL")
      --wordlist-type string                 Type of wordlist to use automatically (directories, files) (default "DIRECTORIES")

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
Capture and analyze web pages to extract content, take screenshots, and perform various page-level analysis.

Usage:
  webscan discover page [flags]

Flags:
      --browserbase-countries strings              List of countries to use for Browserbase proxy
      --browserbase-project string                 Browserbase project ID
      --browserbase-proxy                          Use Browserbase proxy for requests
      --browserbase-token string                   Browserbase API token for cloud browser access
      --headless-path string                       Path to headless browser executable
  -h, --help                                       help for page
      --max-redirects int                          Maximum number of redirects to follow (default 10)
      --min-dom-stabalize-time int                 Minimum time to wait for DOM stabilization in seconds (default 20)
      --request-method string                      Request method to use (standard, headless, browserbase) (default "HEADLESS")
      --response-codes string                      Response codes to consider as valid responses (default "200-299")
      --screenshot                                 Capture a screenshot of the page
      --target string                              URL target to capture and analyze
      --timeout int                                Timeout per request in seconds (default 180)
      --verify-tls                                 Verify TLS certificates when making HTTPS requests

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
webscan discover probe --targets https://example.com --request-method HEADLESS --headless-path /headless-shell/run.sh
```

#### Help Text
```bash
webscan discover probe -h
Probe target URLs to identify if they are running web applications and determine their basic characteristics.

Usage:
  webscan discover probe [flags]

Flags:
      --browserbase-countries strings   List of countries to use for Browserbase proxy
      --browserbase-project string      Browserbase project ID
      --browserbase-proxy               Use Browserbase proxy for requests
      --browserbase-token string        Browserbase API token for cloud browser access
      --headless-path string            Path to headless browser executable
  -h, --help                            help for probe
      --max-redirects int               Maximum number of redirects to follow (default 10)
      --min-dom-stabalize-time int      Minimum time to wait for DOM stabilization in seconds (default 20)
      --protocol string                 Protocol to use for the probe (HTTP, HTTPS)
      --request-method string           Request method to use (standard, headless, browserbase) (default "STANDARD")
      --targets strings                 URL targets to probe for web applications
      --timeout int                     Timeout per request in seconds (default 180)
      --verify-tls                      Verify TLS certificates when making HTTPS requests

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
Discover and analyze web routes to map application structure, identify endpoints, and detect potential vulnerabilities.

Usage:
  webscan discover route [flags]

Flags:
      --browserbase-countries strings   List of countries to use for Browserbase proxy
      --browserbase-project string      Browserbase project ID
      --browserbase-proxy               Use Browserbase proxy for requests
      --browserbase-token string        Browserbase API token for cloud browser access
      --collect-static-assets           Collect static assets from route discovery
      --headless-path string            Path to headless browser executable
  -h, --help                            help for route
      --ignore-cross-domain-routes             Ignore discovered routes whose host is not the target host or a subdomain of it (default true)
      --ignore-cross-domain-static-assets      Ignore discovered static assets whose host is not the target host or a subdomain of it (default true)
      --max-redirects int               Maximum number of redirects to follow (default 10)
      --min-dom-stabalize-time int      Minimum time to wait for DOM stabilization in seconds (default 20)
      --request-method string           Request method to use (standard, headless, browserbase) (default "HEADLESS")
      --spider-depth int                Maximum depth for route spidering (default 1)
      --target string                   URL target to discover routes from
      --threads int                     Number of concurrent threads for scanning
      --timeout int                     Timeout per request in seconds (default 90)
      --verify-tls                      Verify TLS certificates when making HTTPS requests

Global Flags:
  -o, --output string        Output format (signal, json, yaml). Default value is signal (default "signal")
  -f, --output-file string   Path to output file. If blank, will output to STDOUT
  -q, --quiet                Suppress output
  -v, --verbose              Verbose output
```

### SaaS

Gather SaaS information given an organization name.

#### Usage
```bash
webscan discover saas --orgs example
```

#### Help Text
```bash
webscan discover saas -h
Gather SaaS information given an organization name

Usage:
  webscan discover saas [flags]

Flags:
      --browserbase-countries strings   List of countries to use for the proxy
      --browserbase-project string      Browserbase project ID
      --browserbase-proxy               Instruct Browserbase to use a proxy
      --browserbase-token string        Browserbase API token
      --headless-path string            Path to a headless browser executable
  -h, --help                            help for saas
      --max-redirects int               Maximum number of redirects to follow (default 10)
      --min-dom-stabalize-time int      Minimum time in seconds to wait for DOM to stabilize (default 20)
      --orgs strings                    The organization names to use for discovery
      --request-method string           Request method (headless, browserbase) (default "HEADLESS")
      --saas-companies strings          The specific SaaS companies to use for discovery (Must be present in the SaaS fingerprints file)
      --saas-file-paths strings         Files containing SaaS application fingerprints
      --sso-companies strings           The specific SSO companies to use for discovery (Must be present in the SSO fingerprints file)
      --sso-file-paths strings          Files containing SSO application fingerprints
      --threads int                     Number of concurrent threads for discovery (default 25)
      --timeout int                     Timeout in seconds for the capture (default 90)
      --verify-tls                      Verify TLS certificates when making HTTPS requests

Global Flags:
  -o, --output string        Output format (signal, json, yaml). Default value is signal (default "signal")
  -f, --output-file string   Path to output file. If blank, will output to STDOUT
  -q, --quiet                Suppress output
  -v, --verbose              Verbose output
```
