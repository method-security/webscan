# Routecapture

The `webscan routecapture` command all web routes and URLs from a specified target. It uses the same underlying techniques that `pagecapture` uses to render HTML.

Routes are extracted from the rendered HTML, inline scripts, linked scripts, and inspecting network requests made (when using Browser mode).

## Usage

```bash
webscan routecapture [command]
```

## Commmands

### Browser

#### Usage

```bash
webscan routecapture browser --target https://example.com
```

#### Help Text

```bash
Perform a webpage route capture using a headless browser

Usage:
  webscan routecapture browser [flags]

Flags:
      --browserPath string   Path to a browser executable
  -h, --help                 help for browser

Global Flags:
      --base-urls-only       Only match routes and urls that share the base URLs domain (default true)
  -o, --output string        Output format (signal, json, yaml). Default value is signal (default "signal")
  -f, --output-file string   Path to output file. If blank, will output to STDOUT
  -q, --quiet                Suppress output
      --target string        URL target to perform webpage capture
      --timeout int          Timeout in seconds for the capture (default 30)
  -v, --verbose              Verbose output
```

### Browserbase

#### Usage

```bash
webscan routecapture browserbase --project abc-123 --token xyz-789 --target https://example.com
```

#### Help Text

```bash
Perform a fully rendered webpage route capture using Browserbase. Useful for avoiding bot detection or maintaining stealth

Usage:
  webscan routecapture browserbase [flags]

Flags:
      --country stringArray   List of countries to use for the proxy
  -h, --help                  help for browserbase
      --project string        Browserbase project ID
      --proxy                 Instruct Browserbase to use a proxy
      --token string          Browserbase API token

Global Flags:
      --base-urls-only       Only match routes and urls that share the base URLs domain (default true)
      --browserPath string   Path to a browser executable
  -o, --output string        Output format (signal, json, yaml). Default value is signal (default "signal")
  -f, --output-file string   Path to output file. If blank, will output to STDOUT
  -q, --quiet                Suppress output
      --target string        URL target to perform webpage capture
      --timeout int          Timeout in seconds for the capture (default 30)
  -v, --verbose              Verbose output
```

### Request

#### Usage

```bash
webscan routecapture request --target https://example.com
```

#### Help Text

```bash
Perform a webpage route capture using a basic HTTP/HTTPS request

Usage:
  webscan routecapture request [flags]

Flags:
  -h, --help       help for request
      --insecure   Allow insecure connections

Global Flags:
      --base-urls-only       Only match routes and urls that share the base URLs domain (default true)
      --browserPath string   Path to a browser executable
  -o, --output string        Output format (signal, json, yaml). Default value is signal (default "signal")
  -f, --output-file string   Path to output file. If blank, will output to STDOUT
  -q, --quiet                Suppress output
      --target string        URL target to perform webpage capture
      --timeout int          Timeout in seconds for the capture (default 30)
  -v, --verbose              Verbose output
```