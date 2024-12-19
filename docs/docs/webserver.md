# Webserver

The `webscan webserver` family of commands provides techniques to probe various types of web services looking for exposed information that is useful to security teams.

## Usage

```bash
webscan webserver [command] [flags]
```

## Commands

### Headergrab

#### Usage

```bash
webscan webserver headergrab --targets https://example.com
```

#### Help Text

```bash
webscan webserver headergrab -h
Grab the headers of the webserver

Usage:
  webscan webserver headergrab [flags]

Flags:
  -h, --help              help for headergrab
      --targets strings   URL of target
      --timeout int       Timeout per request (Seconds) (default 3)

Global Flags:
  -o, --output string        Output format (signal, json, yaml). Default value is signal (default "signal")
  -f, --output-file string   Path to output file. If blank, will output to STDOUT
  -q, --quiet                Suppress output
  -v, --verbose              Verbose output
```

### Probe

#### Usage

```bash
webscan webserver probe --targets https://example.com
```

#### Help Text

```bash
webscan webserver probe -h
Perform a web probe against targets to identify existence of web applications

Usage:
  webscan webserver probe [flags]

Flags:
  -h, --help              help for probe
      --targets strings   Address targets to perform web application probing agains, comma delimited list
      --timeout int       Timeout limit in seconds (default 30)

Global Flags:
  -o, --output string        Output format (signal, json, yaml). Default value is signal (default "signal")
  -f, --output-file string   Path to output file. If blank, will output to STDOUT
  -q, --quiet                Suppress output
  -v, --verbose              Verbose output
```

### Ratelimit

#### Usage

```bash
webscan webserver ratelimit --targets https://example.com --maxrequests 10 --timespan 10
```

#### Help Text

```bash
webscan webserver ratelimit -h
Perform detection tests for rate limiting

Usage:
  webscan webserver ratelimit [flags]

Flags:
  -h, --help              help for ratelimit
      --maxrequests int   Number of requests to perform
      --targets strings   URL of target
      --timeout int       Timeout per request (Seconds) (default 3)
      --timespan int      Length of time to send the requests (Seconds)

Global Flags:
  -o, --output string        Output format (signal, json, yaml). Default value is signal (default "signal")
  -f, --output-file string   Path to output file. If blank, will output to STDOUT
  -q, --quiet                Suppress output
  -v, --verbose              Verbose output
```


