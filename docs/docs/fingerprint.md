# Fingerprint

The `webscan fingerprint` command fingerprints a URL by collecting its HTTP Options, TLS Config, and Certificates.

## Usage

```bash
webscan fingerprint --targets https://example.com
```

## Help Text

```bash
webscan fingerprint -h
Perform a fingerprint against a URL target

Usage:
  webscan fingerprint [flags]

Flags:
  -h, --help            help for fingerprint
      --target string   Url target to perform fingerprint

Global Flags:
  -o, --output string        Output format (signal, json, yaml). Default value is signal (default "signal")
  -f, --output-file string   Path to output file. If blank, will output to STDOUT
  -q, --quiet                Suppress output
  -v, --verbose              Verbose output

```
