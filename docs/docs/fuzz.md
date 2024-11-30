# Fuzz

The `webscan fuzz` family of commands conduct basic fuzzing techniques to discover URLs and endpoints that may not be advertised.

## Usage

```bash
webscan fuzz [command]
```

## Commands

### Path

#### Usage

```bash
webscan fuzz path --targets https://example.com --pathlists configs/configs/webwordlistsmall.txt --ignore-base-content-match --timeout 3000
```

#### Help Text

```bash
$ webscan fuzz path -h
Perform a path-based web fuzz against a target

Usage:
  webscan fuzz path [flags]

Flags:
  -h, --help                        help for path
      --ignore-base-content-match   Ignores valid responses with identical size and word length to the base path, typically signifying a web backend redirect (default true)
      --pathlists strings           Path to a file that contains a new line delimited list of paths to fuzz
      --paths strings               File paths to use in attack
      --responsecodes string        Response codes to consider as valid responses (default "200-299")
      --retries int                 Number of attempts per credential pair (default 1)
      --sleep int                   Sleep time between requests (milliseconds)
      --successfulonly              Only show successful attempts
      --targets strings             URL of target
      --timeout int                 Timeout per request (milliseconds) (default 3000)

Global Flags:
  -o, --output string        Output format (signal, json, yaml). Default value is signal (default "signal")
  -f, --output-file string   Path to output file. If blank, will output to STDOUT
  -q, --quiet                Suppress output
  -v, --verbose              Verbose output
```
