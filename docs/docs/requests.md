# Requests

The `webscan requests` command performs a custom request against a URL target as well providing a suite of subcommands to perform specific types of requests.

## Usage

```bash
webscan requests --baseUrl https://example.com --path / --method GET 
```

## Help Text

```bash
webscan requests [command]
Perform a custom reques against a target using specified parameters

Usage:
  webscan requests [flags]
  webscan requests [command]

Available Commands:
  headers     Perform specfic header injection requests

Flags:
      --baseUrl string           Base URL of the target
      --bodyParams string        Body parameters as a JSON string (optional)
      --encodedParams            Request parameters base64 encoded
      --formParams string        Form parameters as a JSON string (optional)
      --headerParams string      Header parameters as a JSON string (optional)
  -h, --help                     help for requests
      --method string            HTTP method to use (GET, POST, etc.)
      --multipartParams string   Multipart form parameters as a JSON string (optional)
      --path string              Path to append to the base URL
      --pathParams string        Path parameters as a JSON string (optional)
      --queryParams string       Query parameters as a JSON string (optional)
      --vulnType strings         Types of vulnerabilities to check (optional)

Global Flags:
  -o, --output string        Output format (signal, json, yaml). Default value is signal (default "signal")
  -f, --output-file string   Path to output file. If blank, will output to STDOUT
  -q, --quiet                Suppress output
  -v, --verbose              Verbose output

Use "webscan requests [command] --help" for more information about a command.
```

## Commmands

### Headers

The `webscan requests headers` command contains a suite of subcommands used to perform header injection requests.

#### Commands

##### ServerOverload

The `webscan requests headers serveroverload` command performs a request against the target server to determine if it is vulnerable to serveroverload header injections.

###### Usage

```bash 
webscan requests headers serveroverload --baseUrl https://example.com --path / --method GET --headerSize 100 --headerName "X-Forwarded-For"
```

###### Help Text

```bash
method requests headers servoverload -h
Perform specfic header injection requests

Usage:
  webscan requests headers [command]

Available Commands:
  serveroverload Server overload header requests.

Flags:
  -h, --help   help for headers

Global Flags:
      --baseUrl string       Base URL of the target
      --method string        HTTP method to use (GET, POST, etc.)
  -o, --output string        Output format (signal, json, yaml). Default value is signal (default "signal")
  -f, --output-file string   Path to output file. If blank, will output to STDOUT
      --path string          Path to append to the base URL
  -q, --quiet                Suppress output
  -v, --verbose              Verbose output
      --vulnType strings     Types of vulnerabilities to check (optional)

Use "webscan requests headers [command] --help" for more information about a command.
```
