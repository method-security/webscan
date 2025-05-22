# Application Commands

The `webscan discover` and `webscan enumerate` commands perform application related scans such as fingerprinting and enumeration.

## Usage

```bash
webscan discover application [flags]
```

## Commands

### Fingerprint

The `webscan discover application` command fingerprints a URL by identifying the web application type.

Fingerprint uses a range of modules as the means for identifying an application type.
For example, `--resource-type CLOUD_BUCKET --modules AWSS3` finds an AWS S3 bucket.

#### Usage

```bash
webscan discover application --resource-type API_APPLICATION --modules GRAPHQL --targets https://example.com
```

#### Help Text

```bash
% webscan discover application -h
Perform application fingerprinting against targets.

The fingerprint command identifies the type of web application running on the target URL.
It supports fingerprinting different resource types including API applications, cloud buckets,
content management systems, frameworks, Kubernetes services, remote access portals, and web servers.
The command accepts a list of modules to run for the specified resource type.

Usage:
  webscan discover application [flags]

Flags:
  -h, --help                     help for application
      --fingerprint-file string  Path to the fingerprint definitions file (default "configs/discover/application/fingerprints.json")
      --modules strings          Specific fingerprinting modules to run
      --resource-type string     Type of resource to fingerprint (API_APPLICATION, CLOUD_BUCKET, CONTENT_MANAGEMENT_SYSTEM, FRAMEWORK, KUBE, REMOTE_ACCESS, WEB_SERVER)
      --successful-only          Only show successful fingerprint matches
      --targets strings          URL targets to perform fingerprinting against
      --timeout int              Timeout per request in seconds (default 30)
      --verify-tls               Verify TLS certificates when making HTTPS requests

Global Flags:
  -o, --output string        Output format (signal, json, yaml). Default value is signal (default "signal")
  -f, --output-file string   Path to output file. If blank, will output to STDOUT
  -q, --quiet                Suppress output
  -v, --verbose              Verbose output

```

### Enumerate

The `webscan enumerate` command contains a suite of subcommands for enumerating targets.

#### Usage
```bash
webscan enumerate [command]
```

#### Commands

##### GraphQL

The `webscan enumerate api-application graphql` command performs a GraphQL enumeration scan against a target.

###### Usage

```bash
webscan enumerate api-application graphql --target https://example.com
```

###### Help Text
```bash
webscan enumerate api-application graphql -h
Perform a GraphQL enumeration scan against a target.
		
This involves querying the GraphQL schema to discover available types, queries, mutations, and subscriptions, 
and extracting details about the fields and their types.

Usage:
  webscan enumerate api-application graphql [flags]

Flags:
  -h, --help            help for graphql
      --target string   URL target to perform GraphQL enumeration against

Global Flags:
  -o, --output string        Output format (signal, json, yaml). Default value is signal (default "signal")
  -f, --output-file string   Path to output file. If blank, will output to STDOUT
  -q, --quiet                Suppress output
  -v, --verbose              Verbose output
```

##### K8s

The `webscan enumerate kube` command performs a Kubernetes enumeration scan against a target.

###### Usage

```bash
webscan enumerate kube --target https://example.com --no-sandbox
```

###### Help Text
```bash
Perform a K8s API enumeration against a target.

Usage:
  webscan enumerate kube [flags]

Flags:
  -h, --help            help for k8s
      --target string   URL target to perform K8s enumeration against
      --timeout int     Timeout per request (seconds) (default 5)

Global Flags:
  -o, --output string        Output format (signal, json, yaml). Default value is signal (default "signal")
  -f, --output-file string   Path to output file. If blank, will output to STDOUT
  -q, --quiet                Suppress output
  -v, --verbose              Verbose output
```

##### Swagger

The `webscan enumerate api-application swagger` command performs a Swagger enumeration scan against a target.

###### Usage

```bash
webscan enumerate api-application swagger --target https://example.com --no-sandbox
```

###### Help Text
```bash
Perform a Swagger enumeration scan against a target.
		
This involves fetching and parsing the Swagger (OpenAPI) documentation to extract details about the available endpoints, 
HTTP methods, query parameters, and authentication mechanisms.

Usage:
  webscan enumerate api-application swagger [flags]

Flags:
  -h, --help            help for swagger
      --no-sandbox      Disable sandbox mode for Swagger scan
      --target string   URL target to perform Swagger enumeration against

Global Flags:
  -o, --output string        Output format (signal, json, yaml). Default value is signal (default "signal")
  -f, --output-file string   Path to output file. If blank, will output to STDOUT
  -q, --quiet                Suppress output
  -v, --verbose              Verbose output
```

##### WordPress

Perform WordPress specific enumeration scans against a target

###### Usage

```bash
webscan enumerate cms wordpress [command]
```

###### Commands

####### Plugins

Attempt to enumerate WordPress plugins on a target.


######## Usage

```bash
webscan enumerate cms wordpress plugins --targets https://example.com
```

######### Help Text

```bash

Attempt to enumerate WordPress plugins on a target.

Usage:
  webscan enumerate cms wordpress plugins [flags]

Flags:
      --plugins strings                     WordPress plugins to use for enumeration
      --plugins-file-paths strings          File paths containing WordPress plugins to use for enumeration (default [configs/wordpress_plugins.txt])
  -h, --help                                help for plugins
      --targets strings                     URL targets to perform WordPress plugins enumeration against
      --timeout int                         Timeout per request (seconds) (default 30)
      --threads int                         Number of threads to use during enumeration (default is number of CPUs)

Global Flags:
  -o, --output string        Output format (signal, json, yaml). Default value is signal (default "signal")
  -f, --output-file string   Path to output file. If blank, will output to STDOUT
  -q, --quiet                Suppress output
  -v, --verbose              Verbose output
```
