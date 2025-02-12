# Url

The `webscan url` command performs various types of URL scanning.

## Usage

```bash
webscan url [command] [flags]
```

## Commands

### Fingerprint

#### Usage

```bash
webscan url fingerprint --targets https://example.com
```

#### Help Text

```bash
webscan url fingerprint -h
Given a URL target, grab the HTTP headers to enable further analysis on specific headers and their values.

Usage:
  webscan url fingerprint [flags]

Flags:
  -h, --help            help for fingerprint
      --target string   Url target to perform fingerprint

Global Flags:
  -o, --output string        Output format (signal, json, yaml). Default value is signal (default "signal")
  -f, --output-file string   Path to output file. If blank, will output to STDOUT
  -q, --quiet                Suppress output
  -v, --verbose              Verbose output

```
