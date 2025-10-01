# MaaS CLI

Interactive CLI with slash-command palette and Keycloak device-flow authentication.

## Build

```bash
go build -o maas-cli
```

## Usage

Interactive mode:
```bash
./maas-cli
```

Type `/` to discover commands, `/login` to authenticate, `/help` for all commands, `/exit` to quit.

One-shot login:
```bash
./maas-cli login
```

## Commands

Available slash commands in interactive mode:

- `/login` - Authenticate using device flow
- `/create-key [name]` - Generate a new API key
- `/create-team` - Create a new team with rate limits
- `/list-keys` - Show existing API keys
- `/list-teams` - Show existing teams
- `/usage [namespace] [range]` - View recent usage totals
- `/models` - See available models
- `/help` - Show available commands
- `/exit` - Quit

## Options

Commands support these flags:
- `--show-curl` - Print the curl command and exit
- `--show-raw` - Show raw output from the curl command

Example: `/list-keys --show-curl`