# App

The `webscan app` command performs various application scans such as fingerprinting and enumeration.

## Usage

```bash
webscan app [command]
```

## Commands

### Fingerprint

The `webscan app fingerprint` command fingerprints a URL by identifying the web application type.

Fingerprint uses a randge of modules as the means for identifying an application type.
For example, `--resourcetype APIAPPLICATION  --modules SWAGGER` finds an active Swagger API. `--resourcetype APIAPPLICATION  --modules AWSS3` finds AWS S3 buckets.

#### Usage

```bash
webscan app fingerprint --resourcetype APIAPPLICATION  --modules GRAPHQL --targets https://example.com 
```

#### Help Text

```bash
% method app fingerprint -h
Perform a fingerprinting scan against a target using specified types.
		
The fingerprint command identifies the type of web application running on the target URL.
It supports fingerprinting different resource types including API applications (FastAPI, Swagger, gRPC, GraphQL, K8s), and 
cloud buckets (AWSS3, AzureBlob). The command accepts a list of modules to run
for the specified resource type.

Usage:
  webscan app fingerprint [flags]

Flags:
  -h, --help                  help for fingerprint
      --modules strings       Modules to run (APIApplication: FASTAPI, GRAPHQL, GRPC, SWAGGER, K8S, WORDPRESS; CloudBucket: AWSS3, AZUREBLOB; WebApplication: APACHE, NGINX)
      --resourcetype string   Resource type to fingerprint (APIAPPLICATION, CLOUDBUCKET, WEBAPPLICATION)
      --successfulonly        Only show successful attempts
      --targets strings       URL target to perform fingerprint against
      --timeout int           Timeout per request (seconds) (default 30)

Global Flags:
  -o, --output string        Output format (signal, json, yaml). Default value is signal (default "signal")
  -f, --output-file string   Path to output file. If blank, will output to STDOUT
  -q, --quiet                Suppress output
  -v, --verbose              Verbose output

```

### Enumerate

The `webscan app enumerate` command contains a suite of subcommands for enumerating API applications.

#### Usage
```bash
webscan app enumerate [command]
```

#### Commands

##### GraphQL

The `webscan app enumerate graphql` command performs a GraphQL enumeration scan against a target.

###### Usage

```bash
webscan app enumerate graphql --target https://example.com
```

###### Help Text
```bash 
method app enumerate graphql  -h
Perform a GraphQL enumeration scan against a target.
		
This involves querying the GraphQL schema to discover available types, queries, mutations, and subscriptions, 
and extracting details about the fields and their types.

Usage:
  webscan app enumerate graphql [flags]

Flags:
  -h, --help            help for graphql
      --target string   URL target to perform GraphQL enumeration against

Global Flags:
  -o, --output string        Output format (signal, json, yaml). Default value is signal (default "signal")
  -f, --output-file string   Path to output file. If blank, will output to STDOUT
  -q, --quiet                Suppress output
  -v, --verbose              Verbose output
```

##### gRPC

The `webscan app enumerate grpc` command performs a gRPC enumeration scan against a target.

###### Usage

```bash
webscan app enumerate grpc --target grpc.example.com:443
```

###### Help Text
```bash
webscan app enumerate grpc -h
Perform a gRPC enumeration scan against a target.
		
This involves connecting to the gRPC server, using reflection to discover available services and methods, 
and extracting details about the methods, including their input and output types.

Usage:
  webscan app enumerate grpc [flags]

Flags:
  -h, --help            help for grpc
      --target string   URL target to perform gRPC enumeration against

Global Flags:
  -o, --output string        Output format (signal, json, yaml). Default value is signal (default "signal")
  -f, --output-file string   Path to output file. If blank, will output to STDOUT
  -q, --quiet                Suppress output
  -v, --verbose              Verbose output
```

##### K8s

The `webscan app enumerate k8s` command performs a Kubernetes enumeration scan against a target.

###### Usage

```bash 
webscan app enumerate k8s --target https://example.com --no-sandbox
```

###### Help Text
```bash
Perform a K8s API enumeration against a target.

Usage:
  webscan app enumerate k8s [flags]

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

The `webscan app enumerate swagger` command performs a Swagger enumeration scan against a target.

###### Usage

```bash 
webscan app enumerate swagger --target https://example.com --no-sandbox
```

###### Help Text
```bash
Perform a Swagger enumeration scan against a target.
		
This involves fetching and parsing the Swagger (OpenAPI) documentation to extract details about the available endpoints, 
HTTP methods, query parameters, and authentication mechanisms.

Usage:
  webscan app enumerate swagger [flags]

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
