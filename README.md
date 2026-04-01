# MaaS CLI

`maas-cli` is a CLI for the **Models-as-a-Service** platform. It wraps the documented API endpoints into simple commands — from API key creation through model discovery to interactive chat.

## Build

```bash
go build -o maas-cli .
```

## Prerequisites

- `oc` and `kubectl` installed
- Logged in to OpenShift (`oc login ...`)
- MaaS deployed and reachable via `https://maas.<cluster-domain>`

## Validation / Quick Start

This is the CLI equivalent of the curl-based validation flow from the deployment guide.

### With curl (what the docs show)

```bash
# Discover gateway
HOST=$(kubectl get maasmodelref facebook-opt-125m-simulated -n llm \
  -o jsonpath='{.status.endpoint}' | sed -E 's#(https://[^/]+).*#\1#')

# Mint API key
TOKEN=$(oc whoami -t)
API_KEY=$(curl -sSk -X POST "$HOST/maas-api/v1/api-keys" \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"name":"validate-key","expiresIn":"2h"}' | jq -r '.key')

# Chat
curl -sSk "$HOST/llm/facebook-opt-125m-simulated/v1/chat/completions" \
  -H 'Content-Type: application/json' \
  -H "Authorization: Bearer $API_KEY" \
  -d '{"model":"facebook/opt-125m","messages":[{"role":"user","content":"hello"}],"max_tokens":8}' | jq .
```

### With maas-cli (same thing, three commands)

```bash
# 1) Set the endpoint
#    Option A: auto-discover from cluster (requires kubectl + oc login)
maas-cli endpoint
#    Option B: set it explicitly (if auto-discovery doesn't work or you're off-cluster)
export MAAS_API_URL=https://maas.apps.your-cluster.example.com

# 2) Mint an API key (auto-runs oc whoami -t)
maas-cli create-api-key --name validate-key --expires-in 2h

# 3) Chat with the model
maas-cli chat --prompt "hello" --max-tokens 8
```

> **Note:** Auto-discovery relies on `kubectl get ingresses.config.openshift.io` which may not work if you're running outside the cluster, don't have cluster-reader permissions, or are using a non-OpenShift cluster. In those cases, set `MAAS_API_URL` or pass `--maas-api-url` directly.

The CLI saves the API key to the session, discovers the model URL via `/v1/models`, and sends the chat request — no jq, no variable juggling.

### From the interactive shell

```
$ ./maas-cli

 ███░   ███░ █████░  █████░ ███████░     ██████░██░     ██░
 ████░ ████░██░░░██░██░░░██░██░░░░░░    ██░░░░░░██░     ██░
 ██░████░██░███████░███████░███████░    ██░     ██░     ██░
 ██░░██░░██░██░░░██░██░░░██░░░░░░██░    ██░     ██░     ██░
 ██░ ░░░ ██░██░  ██░██░  ██░███████░    ░██████░███████░██░
 ░░░      ░░░░░   ░░░░░   ░░░░░░░░░░      ░░░░░░░░░░░░░░░░░
 ...

  Endpoint: https://maas.apps.your-cluster.example.com
  API Key:  sk-oai-qwibNpZohbug...
  Model:    facebook/opt-125m

  Type / to see commands, /help for details, /exit or Ctrl-D to quit.

maas> /endpoint
https://maas.apps.your-cluster.example.com

maas> /create-api-key --name validate-key --expires-in 2h
{
  "createdAt": "2026-04-01T06:33:53Z",
  "ephemeral": false,
  "expiresAt": "2026-04-01T08:33:53Z",
  "id": "db61da9e-359c-4d9d-a53f-c2297741b5ea",
  "key": "sk-oai-qwibNpZohbug4E94...",
  "keyPrefix": "sk-oai-qwibNpZohbug...",
  "name": "validate-key",
  "subscription": "simulator-subscription"
}
Saved API URL and API key in ~/.maas-cli/session.json

maas> /models
{
  "data": [
    {
      "id": "facebook/opt-125m",
      "url": "https://maas.apps.your-cluster.example.com/llm/facebook-opt-125m-simulated",
      "ready": true,
      ...
    }
  ]
}

maas> /chat hello
  Model: facebook/opt-125m
  URL:   https://maas.apps.your-cluster.example.com/llm/facebook-opt-125m-simulated/v1/chat/completions

assistant> I am fine, how are you today?

maas> /chat what can you help me with?
assistant> I can help you with a wide variety of tasks...

maas> /chat-history
[user] hello
[assistant] I am fine, how are you today?
[user] what can you help me with?
[assistant] I can help you with a wide variety of tasks...

maas> /chat-clear
Chat history cleared.

maas> /exit
Goodbye!
```

Each step saves state to the session, so you never re-type endpoints or keys.

### Pointing at a different endpoint

If auto-detection doesn't work (e.g. remote cluster, no `kubectl`), set the endpoint explicitly:

```bash
# Environment variable
export MAAS_API_URL=https://maas.apps.your-cluster.example.com

# Or per-command flag
maas-cli models --maas-api-url https://maas.apps.your-cluster.example.com

# Or once — it gets saved to the session
maas-cli endpoint --maas-api-url https://maas.apps.your-cluster.example.com
```

## Interactive Shell

Run `maas-cli` with no arguments to enter the interactive REPL:

```
$ ./maas-cli

 ███░   ███░ █████░  █████░ ███████░     ██████░██░     ██░
 ████░ ████░██░░░██░██░░░██░██░░░░░░    ██░░░░░░██░     ██░
 ██░████░██░███████░███████░███████░    ██░     ██░     ██░
 ██░░██░░██░██░░░██░██░░░██░░░░░░██░    ██░     ██░     ██░
 ██░ ░░░ ██░██░  ██░██░  ██░███████░    ░██████░███████░██░
 ░░░      ░░░░░   ░░░░░   ░░░░░░░░░░      ░░░░░░░░░░░░░░░░░

  Type / to see commands, /help for details, /exit or Ctrl-D to quit.

maas>
```

Type `/` and tab-complete through commands. The REPL shows your current session state (endpoint, API key, model) on startup.

### REPL Commands

| Command | Description |
|---------|-------------|
| `/endpoint` | Detect MaaS API URL from cluster |
| `/create-api-key` | Create an API key (+ flags like `--name`, `--expires-in`) |
| `/revoke-api-key` | Revoke an API key (`--key-id`) |
| `/list-api-keys` | Search/list your API keys |
| `/subscriptions` | List accessible subscriptions |
| `/models` | List available models |
| `/chat <message>` | Send a chat message (multi-turn history kept) |
| `/chat-clear` | Clear chat conversation history |
| `/chat-history` | Show chat conversation so far |
| `/session` | Show current session state |
| `/help` | Show available commands |
| `/exit`, `Ctrl-D` | Quit |

## CLI Commands

All commands are also available directly from the shell:

| Command | Description |
|---------|-------------|
| `maas-cli endpoint` | Auto-detect MaaS API URL from the cluster |
| `maas-cli create-api-key` | Mint an API key (`POST /maas-api/v1/api-keys`) |
| `maas-cli revoke-api-key` | Revoke a key (`DELETE /maas-api/v1/api-keys/{id}`) |
| `maas-cli list-api-keys` | Search/list keys (`POST /maas-api/v1/api-keys/search`) |
| `maas-cli subscriptions` | List accessible subscriptions (`GET /v1/subscriptions`) |
| `maas-cli models` | List available models (`GET /v1/models`) |
| `maas-cli chat` | Single-shot chat (`POST {model_url}/v1/chat/completions`) |

## Demo Walkthrough

```bash
# 1) Discover the MaaS endpoint
MAAS_API_URL=$(maas-cli endpoint)

# 2) Mint an API key (uses `oc whoami -t` automatically)
maas-cli create-api-key \
  --maas-api-url "$MAAS_API_URL" \
  --name demo-key \
  --description "Demo key" \
  --expires-in 1h

# 3) See what subscriptions you have access to
maas-cli subscriptions

# 4) List available models
maas-cli models

# 5) Send a single prompt
maas-cli chat --prompt "What is Kubernetes?"

# 6) Or use the REPL for multi-turn chat
./maas-cli
maas> /chat What is Kubernetes?
maas> /chat Tell me more about pods
```

The CLI saves the API URL, API key, and last-used model to `~/.maas-cli/session.json`, so subsequent commands don't need flags repeated.

## Key Management

```bash
# Create a key bound to a specific subscription
maas-cli create-api-key --name prod-key --subscription premium --expires-in 90d

# List your active keys
maas-cli list-api-keys

# Include revoked/expired keys
maas-cli list-api-keys --status active,revoked,expired

# Revoke a specific key
maas-cli revoke-api-key --key-id key_abc123

# Revoke the last key you created (from session)
maas-cli revoke-api-key
```

## Command Flags

### `create-api-key`

| Flag | Description |
|------|-------------|
| `--maas-api-url` | Override endpoint auto-detection |
| `--oc-token` | Bypass `oc whoami -t` |
| `--name` | Key name (default: `maas-cli-key`) |
| `--description` | Key description |
| `--expires-in` | e.g. `90d`, `30d`, `1h` |
| `--subscription` | Bind key to a MaaSSubscription |
| `--ephemeral` | Short-lived key (max 1h) |
| `--no-save` | Don't save to session |
| `--show-curl` | Print equivalent curl only |

### `revoke-api-key`

| Flag | Description |
|------|-------------|
| `--key-id` | Key ID to revoke (defaults to session) |
| `--oc-token` | OpenShift token |
| `--show-curl` | Print equivalent curl only |

### `list-api-keys`

| Flag | Description |
|------|-------------|
| `--status` | Filter: `active`, `revoked`, `expired` (comma-separated) |
| `--include-ephemeral` | Include ephemeral keys |
| `--sort-by` | `created_at`, `expires_at`, `last_used_at`, `name` |
| `--sort-order` | `asc` or `desc` |
| `--limit` | Max results 1-100 (default: 50) |
| `--offset` | Pagination offset |
| `--show-curl` | Print equivalent curl only |

### `subscriptions`

| Flag | Description |
|------|-------------|
| `--oc-token` | OpenShift token |
| `--model-id` | Filter subscriptions for a specific model |
| `--show-curl` | Print equivalent curl only |

### `models`

| Flag | Description |
|------|-------------|
| `--oc-token` | OpenShift token |
| `--subscription` | `X-MaaS-Subscription` header |
| `--show-curl` | Print equivalent curl only |

### `chat`

| Flag | Description |
|------|-------------|
| `--prompt` | User prompt |
| `--model-id` | Pick model from `/v1/models` |
| `--model-url` | Call explicit model endpoint directly |
| `--max-tokens` | Max tokens (default: 100) |
| `--stream` | Streaming completion mode |
| `--show-curl` | Print equivalent curl only |

## Session

By default, the CLI stores state in `~/.maas-cli/session.json`:

- `maas_api_url` — auto-detected or explicit
- `api_key` / `api_key_id` — last minted key
- `subscription` — bound subscription
- `last_model_id` / `last_model_url` — last used model

This allows progressive use: after `create-api-key`, subsequent commands work without repeating flags.

## Environment Variables

| Variable | Description |
|----------|-------------|
| `MAAS_API_URL` | MaaS API base URL |
| `MAAS_API_KEY` | API key for model access |
| `OC_TOKEN` | OpenShift token (bypass `oc whoami -t`) |

## `--show-curl`

Every command supports `--show-curl` to print the equivalent `curl` command without making a live request. Useful for debugging, documentation, or running in a different terminal.
