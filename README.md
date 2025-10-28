# MaaS CLI

Interactive CLI for MaaS (Model as a Service) with OpenShift authentication and service account token management.

## Build

```bash
go build -o maas-cli main.go base.go
```

## Usage

Interactive mode (default - base mode):
```bash
./maas-cli
```

Type `/` to discover commands, `/get-token` to create a service account token, `/help` for all commands, `/exit` to quit.

One-shot commands:
```bash
./maas-cli login        # Show login instructions
./maas-cli interactive  # Start interactive REPL
```

## Prerequisites

- OpenShift cluster access with `oc` and `kubectl` installed
- Active OpenShift login session (e.g. `oc login`)
- MaaS deployed in the cluster

## Commands

Available slash commands in interactive mode:

- `/get-endpoint` - Get MaaS gateway endpoint from OpenShift cluster
- `/get-token [expiration]` - Create a new service account token (default: 8h, examples: 1h, 30m, 24h)
- `/models` - List available models
- `/test-model [model-name] [prompt]` - Test model endpoint with a prompt
- `/test-auth [model-name]` - Test authorization (expect 401 without token)
- `/test-rate-limit [model-name]` - Test rate limiting with concurrent requests
- `/validate` - Run all validation steps like deployment script
- `/metrics` - View metrics and statistics
- `/login` - Authenticate using OpenShift token
- `/help` - Show available commands
- `/exit` - Quit

## Token Expiration

The `/get-token` command supports custom expiration times:

```bash
/get-token          # Default 8 hours
/get-token 1h       # 1 hour
/get-token 30m      # 30 minutes
/get-token 24h      # 24 hours
/get-token 2h30m    # 2 hours and 30 minutes
```

Supported time units:
- `h` = hours
- `m` = minutes
- `s` = seconds

## Options

Commands support these flags:
- `--show-curl` - Print the curl command and exit
- `--show-raw` - Show raw output from the curl command

Example: `/get-token 4h --show-curl`

## Quick Start

1. **Login to OpenShift:**
   ```bash
   oc login <your-cluster-url>
   ```

2. **Start the CLI:**
   ```bash
   ./maas-cli
   ```

3. **Create a service account token:**
   ```
   /get-token
   ```

4. **List available models:**
   ```
   /models
   ```

5. **Test a model with a chat completion:**
   ```
   # Defualts to the first model in the list
   /test-model
   # Specify a model ID from the /models listing
   /test-model facebook/opt-125m Mewdy Partner
   ```

## Validation

Run the complete validation suite to test all MaaS components:

```
/validate
```

This will:
1. Verify cluster connectivity and gateway endpoint
2. Check service account token
3. Test model endpoints
4. Verify authorization is working (expect 401 without token)
5. Test rate limiting with concurrent requests

## Session Storage

Tokens are automatically stored in `~/.maas-cli/base-session.json` for reuse across CLI sessions. The token includes:
- Service account token
- MaaS API base URL
- Expiration time
- Creation time

Tokens are automatically validated and you'll be prompted to create a new one when expired.

## Architecture

The base mode uses:
- **Authentication**: OpenShift OAuth with service account tokens
- **API**: MaaS billing API (`/maas-api/v1/tokens`, `/maas-api/v1/models`)
- **Inference**: Model endpoints (`/llm/{model}/v1/chat/completions`)
- **Auto-detection**: Cluster domain and MaaS gateway endpoint

## Experimental IDP Mode

For deployments using Keycloak device-flow authentication with PostgreSQL backing, see [README-experimental.md](./README-experimental.md).

To use IDP mode:
```bash
./maas-cli --idp
```

