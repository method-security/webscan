# Capabilities

webscan offers a variety of scanning techniques to security teams working to gain a better handle on what web applications they have deployed across cloud providers and on-premise environments. Each of the below pages offers you an in depth look at a webscan capability related to a unique scanning technique.

- [Application Commands](./app.md)


## Top Level Flags

webscan has several top level flags that can be used on any subcommand. These include:

```bash
Flags:
  -h, --help                 help for webscan
  -o, --output string        Output format (signal, json, yaml). Default value is signal (default "signal")
  -f, --output-file string   Path to output file. If blank, will output to STDOUT
  -q, --quiet                Suppress output
  -v, --verbose              Verbose output
```

## Version Command

Run `webscan version` to get the exact version information for your binary

## Output Formats

For more information on the various output formats that are supported by webscan, see the [Output Formats](https://method-security.github.io/docs/output.html) page in our organization wide documentation.
