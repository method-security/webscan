# Webserver

The `webscan webserver` family of commands provides techniques to probe various types of web services looking for misconfigurations, vulnerabilities, and exposed information that is useful to security teams.

## Commands

### Probe

#### Usage

```bash
webscan webserver probe --targets https://example.com,https://anotherexample.dev
```

#### Help Text

```bash
webscan probe webserver -h
Perform a web probe against targets to identify existence of web servers

Usage:
  webscan probe webserver [flags]

Flags:
  -h, --help             help for webserver
      --targets string   Address targets to perform webserver probing agains, comma delimited list
      --timeout int      Timeout limit in seconds

Global Flags:
  -o, --output string        Output format (signal, json, yaml). Default value is signal (default "signal")
  -f, --output-file string   Path to output file. If blank, will output to STDOUT
  -q, --quiet                Suppress output
  -v, --verbose              Verbose output
```

### Enumerate

#### Usage

```bash
webscan webserver enumerate --targets https://example.com --server nginx --modules pathtraversal
```

#### Help Text

```bash
webscan webserver enumerate -h
Enumerate a specific type of web server

Usage:
  webscan webserver enumerate [flags]

Flags:
  -h, --help              help for enumerate
      --modules strings   Server specfic modules to run (default all)
      --server string     Server type to target (nginx, apache)
      --successfulonly    Only show successful attempts
      --targets strings   Address of target
      --timeout int       Timeout limit in milliseconds (default 5000)

Global Flags:
  -o, --output string        Output format (signal, json, yaml). Default value is signal (default "signal")
  -f, --output-file string   Path to output file. If blank, will output to STDOUT
  -q, --quiet                Suppress output
  -v, --verbose              Verbose output
```


### Validate

#### Usage

```bash
webscan webserver validate --targets https://example.com --server APACHE --modules RCEMODFILE
```

#### Help Text

```bash
webscan webserver validate -h
Preform validation against a specific type of web server

Usage:
  webscan webserver validate [flags]

Flags:
  -h, --help              help for validate
      --modules strings   Server specfic modules to run (default all)
      --server string     Server type to target (nginx, apache)
      --successfulonly    Only show successful attempts
      --targets strings   Address of target
      --timeout int       Timeout limit in milliseconds (default 5000)

Global Flags:
  -o, --output string        Output format (signal, json, yaml). Default value is signal (default "signal")
  -f, --output-file string   Path to output file. If blank, will output to STDOUT
  -q, --quiet                Suppress output
  -v, --verbose              Verbose output
```
