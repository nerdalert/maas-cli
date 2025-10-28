package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"text/tabwriter"
	"time"

	survey "github.com/AlecAivazis/survey/v2"
	prompt "github.com/c-bata/go-prompt"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
	"math"
	"regexp"
)

const (
	// Legacy IDP defaults (used when --idp flag is set)
	defaultIssuer      = "https://keycloak.apps.maas2.octo-emerging.redhataicoe.com/realms/maas"
	defaultControlBase = "http://key-manager.db.apps.maas2.octo-emerging.redhataicoe.com"
	defaultDataBase    = "http://simulator.db.apps.maas2.octo-emerging.redhataicoe.com"

	// Base mode API defaults
	defaultMaasAPIBase = "" // Will be auto-detected from OpenShift cluster

	cliBanner = `
 ███░   ███░ █████░  █████░ ███████░     ██████░██░     ██░
 ████░ ████░██░░░██░██░░░██░██░░░░░░    ██░░░░░░██░     ██░
 ██░████░██░███████░███████░███████░    ██░     ██░     ██░
 ██░░██░░██░██░░░██░██░░░██░░░░░░██░    ██░     ██░     ██░
 ██░ ░░░ ██░██░  ██░██░  ██░███████░    ░██████░███████░██░
 ░░░      ░░░░░   ░░░░░   ░░░░░░░░░░      ░░░░░░░░░░░░░░░░░`
)

type DeviceResponse struct {
	DeviceCode              string `json:"device_code"`
	UserCode                string `json:"user_code"`
	VerificationURI         string `json:"verification_uri"`
	VerificationURIComplete string `json:"verification_uri_complete"`
	ExpiresIn               int    `json:"expires_in"`
	Interval                int    `json:"interval"`
}

type TokenResponse struct {
	AccessToken      string `json:"access_token"`
	ExpiresIn        int    `json:"expires_in"`
	RefreshToken     string `json:"refresh_token"`
	RefreshExpiresIn int    `json:"refresh_expires_in"`
	TokenType        string `json:"token_type"`
	Scope            string `json:"scope"`
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description"`
}

func main() {
	// If no subcommand given, start interactive REPL
	if len(os.Args) < 2 {
		startInteractive(false) // default mode (not IDP)
		return
	}

	// Flags
	fs := pflag.NewFlagSet(os.Args[0], pflag.ContinueOnError)
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: %s <command> [flags]\n\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "Commands:\n  login         Authenticate using device flow\n  interactive   Start interactive REPL with slash commands\n\n")
		fmt.Fprintf(os.Stderr, "Flags (for login):\n")
		fs.PrintDefaults()
	}

	// Mode selection
	fs.Bool("idp", false, "Use legacy IDP/Keycloak authentication mode (default: base OpenShift mode)")
	fs.Bool("show-curl", false, "Print curl command only (for execution in another window)")

	// Legacy IDP options (only used when --idp is set)
	fs.String("issuer-url", defaultIssuer, "OIDC issuer base (e.g. https://.../realms/maas)")
	fs.String("hostname", "", "Convenience: Keycloak host (builds issuer as https://<host>/realms/<realm>)")
	fs.String("realm", "maas", "Realm used with --hostname to build issuer URL")
	fs.String("client-id", "maas-client", "OIDC client ID")
	fs.String("client-secret", "maas-client-secret", "OIDC client secret")
	fs.Bool("no-browser", false, "Do not attempt to open browser automatically (alias to disabling --web)")
	fs.Bool("web", true, "Open a browser window for authentication")
	fs.Bool("clipboard", false, "Copy one-time code to clipboard (like gh --clipboard)")
	fs.Bool("with-token", false, "Read access token from stdin instead of performing device flow")
	fs.String("token-file", "", "Read access token from a file (used with --with-token)")
	fs.Duration("timeout", 10*time.Minute, "Overall login timeout")

	// Common options
	fs.Bool("insecure", true, "Allow insecure TLS (skip cert verification)")
	fs.String("control-base", defaultControlBase, "Legacy: Key manager API base URL (used with --idp)")
	fs.String("data-base", defaultDataBase, "Legacy: Inference API base URL (used with --idp)")
	fs.String("maas-api-base", defaultMaasAPIBase, "MaaS API base URL (auto-detected if empty)")

	cmd := os.Args[1]
	args := os.Args[2:]
	if err := fs.Parse(args); err != nil {
		os.Exit(2)
	}

	// Viper setup
	v := viper.New()
	v.SetEnvPrefix("MAAS")
	v.SetEnvKeyReplacer(strings.NewReplacer("-", "_"))
	v.AutomaticEnv()

	v.SetConfigName("config")
	v.SetConfigType("yaml")
	if home, err := os.UserHomeDir(); err == nil {
		v.AddConfigPath(home + "/.maas-cli")
	}
	_ = v.ReadInConfig() // optional

	// Bind flags
	_ = v.BindPFlag("idp", fs.Lookup("idp"))
	_ = v.BindPFlag("show-curl", fs.Lookup("show-curl"))
	_ = v.BindPFlag("issuer-url", fs.Lookup("issuer-url"))
	_ = v.BindPFlag("hostname", fs.Lookup("hostname"))
	_ = v.BindPFlag("realm", fs.Lookup("realm"))
	_ = v.BindPFlag("client-id", fs.Lookup("client-id"))
	_ = v.BindPFlag("client-secret", fs.Lookup("client-secret"))
	_ = v.BindPFlag("insecure", fs.Lookup("insecure"))
	_ = v.BindPFlag("control-base", fs.Lookup("control-base"))
	_ = v.BindPFlag("data-base", fs.Lookup("data-base"))
	_ = v.BindPFlag("maas-api-base", fs.Lookup("maas-api-base"))
	_ = v.BindPFlag("no-browser", fs.Lookup("no-browser"))
	_ = v.BindPFlag("web", fs.Lookup("web"))
	_ = v.BindPFlag("clipboard", fs.Lookup("clipboard"))
	_ = v.BindPFlag("with-token", fs.Lookup("with-token"))
	_ = v.BindPFlag("token-file", fs.Lookup("token-file"))
	_ = v.BindPFlag("timeout", fs.Lookup("timeout"))

	useIDP := v.GetBool("idp")

	switch cmd {
	case "login":
		if err := runLogin(v); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
	case "interactive", "repl":
		startInteractive(useIDP)
	case "help", "-h", "--help":
		fs.Usage()
	default:
		// Fallback to interactive if unknown command
		fmt.Fprintf(os.Stderr, "Unknown command: %s\nStarting interactive mode...\n\n", cmd)
		startInteractive(useIDP)
	}
}

type commandContext struct {
	args     string
	showCurl bool // Print curl command only
	showRaw  bool
	useIDP   bool // Whether to use legacy IDP mode
}

type slashCommand struct {
	Name        string
	Description string
	Usage       string
	Handler     func(ctx *commandContext)
	ArgSuggest  func(args string) []prompt.Suggest
}

func startInteractive(useIDP bool) {
	defer restoreTerminalState()

	fmt.Println(cliBanner)
	fmt.Println()
	if useIDP {
		fmt.Println("MaaS CLI — Interactive Mode (IDP)")
	} else {
		fmt.Println("MaaS CLI — Interactive Mode")
	}
	fmt.Println("Type / to run a command. Use ↑/↓ to move, ↵ to execute, Ctrl+D to quit.")

	cmds := buildCommands(useIDP)
	printCommandOverview(cmds)

	cmdMap := map[string]slashCommand{}
	for _, c := range cmds {
		cmdMap[c.Name] = c
	}

	var exitRequested atomic.Bool

	executor := func(in string) {
		line := strings.TrimSpace(in)
		if line == "" {
			return
		}
		if strings.HasPrefix(line, "/") {
			parts := strings.SplitN(line, " ", 2)
			name := strings.TrimPrefix(parts[0], "/")
			args := ""
			if len(parts) > 1 {
				args = strings.TrimSpace(parts[1])
			}
			if name == "exit" || name == "quit" {
				fmt.Println("Goodbye.")
				exitRequested.Store(true)
				return
			}
			if c, ok := cmdMap[name]; ok {
				fs := pflag.NewFlagSet(name, pflag.ContinueOnError)
				fs.Bool("show-curl", false, "Print curl command only (for execution in another window)")
				fs.Bool("show-raw", false, "Show raw output from the curl command")

				argParts := strings.Fields(args)
				_ = fs.Parse(argParts) // ignore error

				showCurl, _ := fs.GetBool("show-curl")
				showRaw, _ := fs.GetBool("show-raw")

				// The handler needs to get the non-flag arguments
				nonFlagArgs := fs.Args()

				// Create context with flags - useIDP comes from startup flag, not per-command
				ctx := &commandContext{
					args:     strings.Join(nonFlagArgs, " "),
					showCurl: showCurl,
					showRaw:  showRaw,
					useIDP:   useIDP, // Use the global flag from startup
				}

				c.Handler(ctx)

				return
			}
			fmt.Printf("Unknown command: /%s. Type /help for assistance.\n", name)
			return
		}
		fmt.Println("(chat) ", line)
	}

	completer := func(d prompt.Document) []prompt.Suggest {
		text := d.TextBeforeCursor()
		if !strings.HasPrefix(text, "/") {
			return nil
		}
		fields := strings.Fields(text)
		if len(fields) == 0 || (len(fields) == 1 && !strings.Contains(text, " ")) {
			q := strings.TrimPrefix(text, "/")
			return filterCommandSuggest(q, cmds)
		}
		name := strings.TrimPrefix(fields[0], "/")
		if c, ok := cmdMap[name]; ok && c.ArgSuggest != nil {
			argText := strings.TrimPrefix(text, fields[0])
			argText = strings.TrimSpace(argText)
			return c.ArgSuggest(argText)
		}
		return nil
	}

	p := prompt.New(executor, completer,
		prompt.OptionPrefix("▌> "),
		prompt.OptionTitle("maas-cli"),
		prompt.OptionSuggestionTextColor(prompt.DefaultColor),
		prompt.OptionSuggestionBGColor(prompt.DefaultColor),
		prompt.OptionSelectedSuggestionTextColor(prompt.Blue),
		prompt.OptionSelectedSuggestionBGColor(prompt.DefaultColor),
		prompt.OptionDescriptionTextColor(prompt.DefaultColor),
		prompt.OptionDescriptionBGColor(prompt.DefaultColor),
		prompt.OptionSelectedDescriptionTextColor(prompt.Blue),
		prompt.OptionSelectedDescriptionBGColor(prompt.DefaultColor),
		prompt.OptionScrollbarBGColor(prompt.DefaultColor),
		prompt.OptionScrollbarThumbColor(prompt.DefaultColor),
		prompt.OptionCompletionOnDown(),
		prompt.OptionSetExitCheckerOnInput(func(in string, breakline bool) bool {
			return exitRequested.Load()
		}),
	)
	p.Run()
}

func filterCommandSuggest(q string, cmds []slashCommand) []prompt.Suggest {
	out := make([]prompt.Suggest, 0, len(cmds))
	lower := strings.ToLower(q)
	for _, c := range cmds {
		name := "/" + c.Name
		if lower == "" || strings.Contains(strings.ToLower(name), lower) {
			out = append(out, prompt.Suggest{Text: name, Description: c.Description})
		}
	}
	return out
}

func buildCommands(useIDP bool) []slashCommand {
	if useIDP {
		// Legacy IDP mode - complete original functionality
		return []slashCommand{
			{
				Name:        "create-key",
				Description: "Generate a new API key",
				Usage:       "/create-key [name]",
				Handler:     handleCreateKey,
			},
			{
				Name:        "create-team",
				Description: "Create a new team with rate limits",
				Usage:       "/create-team",
				Handler:     handleCreateTeam,
			},
			{
				Name:        "list-keys",
				Description: "Show existing API keys",
				Usage:       "/list-keys",
				Handler:     handleListKeys,
			},
			{
				Name:        "list-teams",
				Description: "Show existing teams",
				Usage:       "/list-teams",
				Handler:     handleListTeams,
			},
			{
				Name:        "usage",
				Description: "View recent usage totals",
				Usage:       "/usage [namespace] [range]",
				Handler:     handleUsage,
			},
			{
				Name:        "models",
				Description: "See available models",
				Usage:       "/models",
				Handler:     handleModels,
			},
			{
				Name:        "login",
				Description: "Authenticate using device flow",
				Usage:       "/login",
				Handler: func(ctx *commandContext) {
					v := buildConfigViper()
					v.Set("skip-prompt", true)
					if err := runLogin(v); err != nil {
						fmt.Fprintf(os.Stderr, "Error: %v\n", err)
					}
				},
			},
			{
				Name:        "help",
				Description: "Show available commands",
				Usage:       "/help",
				Handler: func(ctx *commandContext) {
					printCommandOverview(buildCommands(true))
				},
			},
			{
				Name:        "exit",
				Description: "Exit interactive mode",
				Usage:       "/exit",
				Handler: func(ctx *commandContext) {
					fmt.Println("Goodbye.")
				},
			},
		}
	} else {
		// Base mode - clean MaaS billing API
		return []slashCommand{
			{
				Name:        "get-endpoint",
				Description: "Get MaaS gateway endpoint from OpenShift cluster",
				Usage:       "/get-endpoint",
				Handler:     handleGetEndpointBase,
			},
			{
				Name:        "get-token",
				Description: "Create a new service account token (default: 8h, examples: 1h, 30m, 24h)",
				Usage:       "/get-token [expiration]",
				Handler:     handleGetTokenBase,
			},
			{
				Name:        "models",
				Description: "List available models",
				Usage:       "/models",
				Handler:     handleModelsBase,
			},
			{
				Name:        "test-model",
				Description: "Test model endpoint with a prompt",
				Usage:       "/test-model [model-name] [prompt]",
				Handler:     handleTestModelBase,
			},
			{
				Name:        "test-auth",
				Description: "Test authorization (expect 401 without token)",
				Usage:       "/test-auth [model-name]",
				Handler:     handleTestAuthBase,
			},
			{
				Name:        "test-rate-limit",
				Description: "Test rate limiting with concurrent requests",
				Usage:       "/test-rate-limit [model-name]",
				Handler:     handleTestRateLimitBase,
			},
			{
				Name:        "validate",
				Description: "Run all validation steps like deployment script",
				Usage:       "/validate",
				Handler:     handleValidateBase,
			},
			{
				Name:        "metrics",
				Description: "View metrics and statistics",
				Usage:       "/metrics [live-requests|policy-stats|dashboard]",
				Handler:     handleMetricsBase,
			},
			{
				Name:        "login",
				Description: "Authenticate using OpenShift token",
				Usage:       "/login",
				Handler:     handleLoginBase,
			},
			{
				Name:        "help",
				Description: "Show available commands",
				Usage:       "/help",
				Handler: func(ctx *commandContext) {
					printCommandOverview(buildCommands(false))
				},
			},
			{
				Name:        "exit",
				Description: "Exit interactive mode",
				Usage:       "/exit",
				Handler: func(ctx *commandContext) {
					fmt.Println("Goodbye.")
				},
			},
		}
	}
}

type apiKeyRecord struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Description string    `json:"description,omitempty"`
	Fingerprint string    `json:"fingerprint"`
	CreatedAt   time.Time `json:"created_at"`
	TeamID      string    `json:"team_id,omitempty"`
}

type sessionData struct {
	AccessToken  string    `json:"access_token"`
	RefreshToken string    `json:"refresh_token,omitempty"`
	TokenType    string    `json:"token_type,omitempty"`
	ExpiresAt    time.Time `json:"expires_at,omitempty"`
	ObtainedAt   time.Time `json:"obtained_at"`
}

type usageSummaryResponse struct {
	Namespace   string                 `json:"namespace"`
	Range       string                 `json:"range"`
	Metrics     map[string]usageMetric `json:"metrics"`
	GeneratedAt time.Time              `json:"generated_at"`
}

type usageMetric struct {
	Total        float64   `json:"total"`
	SampleCount  int       `json:"sample_count"`
	LatestValue  float64   `json:"latest_value"`
	LastSampleAt time.Time `json:"last_sample_at"`
}

var (
	errNoSession      = errors.New("not logged in")
	errSessionExpired = errors.New("login expired")
)

var usageRangePattern = regexp.MustCompile(`^[0-9]+(s|m|h|d|w|y)$`)

func (s *sessionData) expired() bool {
	if s == nil {
		return true
	}
	if s.ExpiresAt.IsZero() {
		return false
	}
	return time.Now().After(s.ExpiresAt.Add(-1 * time.Minute))
}

func sessionFilePath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".maas-cli", "session.json"), nil
}

func loadSession() (*sessionData, error) {
	path, err := sessionFilePath()
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	if len(data) == 0 {
		return nil, nil
	}
	var session sessionData
	if err := json.Unmarshal(data, &session); err != nil {
		return nil, err
	}
	return &session, nil
}

func saveSession(session *sessionData) error {
	if session == nil {
		return errors.New("nil session")
	}
	path, err := sessionFilePath()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(session, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o600)
}

func ensureSession() (*sessionData, error) {
	session, err := loadSession()
	if err != nil {
		return nil, err
	}
	if session == nil || session.AccessToken == "" {
		return nil, errNoSession
	}
	if session.expired() {
		return nil, errSessionExpired
	}
	return session, nil
}

func handleSessionError(err error) {
	switch {
	case errors.Is(err, errNoSession):
		fmt.Println("You must login first. Use /login.")
	case errors.Is(err, errSessionExpired):
		fmt.Println("Your login has expired. Run /login to authenticate again.")
	default:
		fmt.Fprintf(os.Stderr, "failed to read session: %v\n", err)
	}
}

func newAPIClient(insecure bool) *http.Client {
	transport := &http.Transport{}
	if insecure {
		transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	}
	transport.DisableCompression = true
	return &http.Client{Timeout: 30 * time.Second, Transport: transport}
}

func ensureProfile(client *http.Client, baseURL, token string) error {
	req, err := http.NewRequest(http.MethodGet, strings.TrimRight(baseURL, "/")+"/profile", nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("profile request failed: %s: %s", resp.Status, strings.TrimSpace(string(b)))
	}
	return nil
}

func printCommandOverview(cmds []slashCommand) {
	fmt.Println("────────────────────────────────────────────────────────")
	fmt.Println("Slash Commands:")
	seen := make(map[string]struct{})
	for _, c := range cmds {
		if _, ok := seen[c.Name]; ok {
			continue
		}
		fmt.Printf("  /%-14s %s\n", c.Name, c.Description)
		seen[c.Name] = struct{}{}
	}
	fmt.Println("────────────────────────────────────────────────────────")
}

func handleCreateKey(ctx *commandContext) {
	alias := strings.TrimSpace(ctx.args)
	if alias == "" && isTTY() {
		prompt := &survey.Input{Message: "Key name"}
		if err := survey.AskOne(prompt, &alias, survey.WithValidator(survey.Required)); err != nil {
			fmt.Fprintf(os.Stderr, "create-key cancelled: %v\n", err)
			return
		}
	}
	alias = strings.TrimSpace(alias)
	if alias == "" {
		fmt.Println("A key name is required. Try /create-key <name>.")
		return
	}

	description := ""
	if isTTY() {
		if err := survey.AskOne(&survey.Input{Message: "Description", Help: "Optional note to recognise this key"}, &description); err != nil {
			fmt.Fprintf(os.Stderr, "create-key cancelled: %v\n", err)
			return
		}
	}

	session, err := ensureSession()
	if err != nil {
		handleSessionError(err)
		return
	}

	v := buildConfigViper()
	controlBase := strings.TrimSpace(v.GetString("control-base"))
	if controlBase == "" {
		fmt.Println("Control plane base URL is not configured. Set MAAS_CONTROL_BASE or --control-base.")
		return
	}

	client := newAPIClient(v.GetBool("insecure"))
	if err := ensureProfile(client, controlBase, session.AccessToken); err != nil {
		fmt.Fprintf(os.Stderr, "failed to bootstrap profile: %v\n", err)
		return
	}

	// First, get available teams for team selection
	teamsReq, err := http.NewRequest(http.MethodGet, strings.TrimRight(controlBase, "/")+"/teams", nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to build teams request: %v\n", err)
		return
	}
	teamsReq.Header.Set("Authorization", "Bearer "+session.AccessToken)

	if ctx.showCurl {
		fmt.Println("# First, list available teams:")
		printCurlCommand(teamsReq)
		fmt.Println()
	}

	teamsResp, err := client.Do(teamsReq)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to fetch teams: %v\n", err)
		return
	}
	defer teamsResp.Body.Close()

	// Parse teams response
	var teamsPayload struct {
		Teams []struct {
			ID    string `json:"id"`
			ExtID string `json:"ext_id"`
			Name  string `json:"name"`
		} `json:"teams"`
	}

	var selectedTeamID string
	if teamsResp.StatusCode < 300 {
		if err := json.NewDecoder(teamsResp.Body).Decode(&teamsPayload); err == nil {
			// Let user select a team if teams are available and we're in TTY mode
			if len(teamsPayload.Teams) > 0 && isTTY() {
				teamOptions := []string{"(default team - use your personal default)"}
				teamMap := map[string]string{"(default team - use your personal default)": ""}

				for _, team := range teamsPayload.Teams {
					option := fmt.Sprintf("%s (%s)", team.Name, team.ExtID)
					teamOptions = append(teamOptions, option)
					teamMap[option] = team.ID
				}

				var selectedOption string
				prompt := &survey.Select{
					Message:  "Select team for the API key",
					Options:  teamOptions,
					Default:  teamOptions[0],
					PageSize: 10,
				}
				if err := survey.AskOne(prompt, &selectedOption); err != nil {
					fmt.Fprintf(os.Stderr, "create-key cancelled: %v\n", err)
					return
				}
				selectedTeamID = teamMap[selectedOption]
			}
		}
	}

	// Prepare key creation request
	keyReq := map[string]interface{}{
		"alias": alias,
	}
	if selectedTeamID != "" {
		keyReq["team_id"] = selectedTeamID
	}

	body, err := json.Marshal(keyReq)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to encode request: %v\n", err)
		return
	}

	createReq, err := http.NewRequest(http.MethodPost, strings.TrimRight(controlBase, "/")+"/users/me/keys", bytes.NewReader(body))
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to build request: %v\n", err)
		return
	}
	createReq.Header.Set("Authorization", "Bearer "+session.AccessToken)
	createReq.Header.Set("Content-Type", "application/json")

	if ctx.showCurl {
		fmt.Println("# Create API key:")
		printCurlCommand(createReq)
		return
	}

	resp, err := client.Do(createReq)
	if err != nil {
		fmt.Fprintf(os.Stderr, "request failed: %v\n", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 300 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		msg := strings.TrimSpace(string(b))
		if msg == "" {
			msg = resp.Status
		}
		fmt.Fprintf(os.Stderr, "create-key failed: %s\n", msg)
		return
	}

	var created struct {
		APIKey    string `json:"api_key"`
		KeyID     string `json:"key_id"`
		TeamID    string `json:"team_id"`
		CreatedAt string `json:"created_at"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&created); err != nil {
		fmt.Fprintf(os.Stderr, "failed to decode response: %v\n", err)
		return
	}
	if created.APIKey == "" {
		fmt.Fprintln(os.Stderr, "create-key failed: API key missing in response")
		return
	}

	fingerprint := keyFingerprint(created.APIKey)
	createdAt := time.Now().UTC()
	if created.CreatedAt != "" {
		if parsed, err := time.Parse(time.RFC3339, created.CreatedAt); err == nil {
			createdAt = parsed
		}
	}

	record := apiKeyRecord{
		ID:          created.KeyID,
		Name:        alias,
		Description: strings.TrimSpace(description),
		Fingerprint: fingerprint,
		CreatedAt:   createdAt,
		TeamID:      created.TeamID,
	}
	if err := upsertKeyRecord(record); err != nil {
		fmt.Fprintf(os.Stderr, "warning: failed to update local key cache: %v\n", err)
	}

	fmt.Printf("✅ API key created successfully!\n")
	fmt.Printf("Name: %s\n", record.Name)
	fmt.Printf("ID: %s\n", record.ID)
	if record.TeamID != "" {
		// Try to find the team name for better display
		teamDisplayName := record.TeamID
		if selectedTeamID != "" {
			// Find the team name from our earlier fetch
			for _, team := range teamsPayload.Teams {
				if team.ID == selectedTeamID {
					teamDisplayName = fmt.Sprintf("%s (%s)", team.Name, team.ExtID)
					break
				}
			}
		}
		fmt.Printf("Team: %s\n", teamDisplayName)
	} else {
		fmt.Printf("Team: (default team)\n")
	}
	fmt.Printf("API key: %s\n", created.APIKey)
	fmt.Printf("Fingerprint: %s\n", record.Fingerprint)
	fmt.Println("Store this value securely; it will only be shown once.")
}

func handleCreateTeam(ctx *commandContext) {
	session, err := ensureSession()
	if err != nil {
		handleSessionError(err)
		return
	}

	v := buildConfigViper()
	controlBase := strings.TrimSpace(v.GetString("control-base"))
	if controlBase == "" {
		fmt.Println("Control plane base URL is not configured. Set MAAS_CONTROL_BASE or --control-base.")
		return
	}

	// Get team name
	teamName := ""
	if isTTY() {
		prompt := &survey.Input{Message: "Team name"}
		if err := survey.AskOne(prompt, &teamName, survey.WithValidator(survey.Required)); err != nil {
			fmt.Fprintf(os.Stderr, "create-team cancelled: %v\n", err)
			return
		}
	} else {
		fmt.Println("A team name is required in interactive mode.")
		return
	}

	// Get external ID (defaults to team name)
	extID := ""
	if isTTY() {
		prompt := &survey.Input{
			Message: "External ID",
			Default: teamName,
			Help:    "External identifier for the team (defaults to team name)",
		}
		if err := survey.AskOne(prompt, &extID); err != nil {
			fmt.Fprintf(os.Stderr, "create-team cancelled: %v\n", err)
			return
		}
	}
	if extID == "" {
		extID = teamName
	}

	// Get description
	description := ""
	if isTTY() {
		if err := survey.AskOne(&survey.Input{Message: "Description", Help: "Optional description for the team"}, &description); err != nil {
			fmt.Fprintf(os.Stderr, "create-team cancelled: %v\n", err)
			return
		}
	}

	// Get rate limit
	rateLimit := 100
	if isTTY() {
		rateString := "100"
		prompt := &survey.Input{
			Message: "Token rate limit",
			Default: "100",
			Help:    "Number of requests allowed in the rate window",
		}
		if err := survey.AskOne(prompt, &rateString); err != nil {
			fmt.Fprintf(os.Stderr, "create-team cancelled: %v\n", err)
			return
		}
		if parsed, err := strconv.Atoi(rateString); err == nil && parsed > 0 {
			rateLimit = parsed
		}
	}

	// Get rate window
	rateWindow := "1m"
	if isTTY() {
		prompt := &survey.Input{
			Message: "Rate window",
			Default: "1m",
			Help:    "Time window for rate limiting (e.g., 1m, 1h, 24h)",
		}
		if err := survey.AskOne(prompt, &rateWindow); err != nil {
			fmt.Fprintf(os.Stderr, "create-team cancelled: %v\n", err)
			return
		}
	}

	client := newAPIClient(v.GetBool("insecure"))
	if err := ensureProfile(client, controlBase, session.AccessToken); err != nil {
		fmt.Fprintf(os.Stderr, "failed to bootstrap profile: %v\n", err)
		return
	}

	// Prepare team creation request
	teamReq := map[string]interface{}{
		"name":        teamName,
		"ext_id":      extID,
		"description": description,
		"rate_limit":  rateLimit,
		"rate_window": rateWindow,
	}

	body, err := json.Marshal(teamReq)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to encode request: %v\n", err)
		return
	}

	createReq, err := http.NewRequest(http.MethodPost, strings.TrimRight(controlBase, "/")+"/teams", bytes.NewReader(body))
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to build request: %v\n", err)
		return
	}
	createReq.Header.Set("Authorization", "Bearer "+session.AccessToken)
	createReq.Header.Set("Content-Type", "application/json")

	if ctx.showCurl {
		fmt.Println("# Create team:")
		printCurlCommand(createReq)
		return
	}

	resp, err := client.Do(createReq)
	if err != nil {
		fmt.Fprintf(os.Stderr, "request failed: %v\n", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 300 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		msg := strings.TrimSpace(string(b))
		if msg == "" {
			msg = resp.Status
		}
		fmt.Fprintf(os.Stderr, "create-team failed: %s\n", msg)
		return
	}

	var created struct {
		ID          string `json:"id"`
		ExtID       string `json:"ext_id"`
		Name        string `json:"name"`
		Description string `json:"description"`
		RateLimit   int    `json:"rate_limit"`
		RateWindow  string `json:"rate_window"`
		CreatedAt   string `json:"created_at"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&created); err != nil {
		fmt.Fprintf(os.Stderr, "failed to decode response: %v\n", err)
		return
	}

	fmt.Printf("✅ Team created successfully!\n")
	fmt.Printf("ID: %s\n", created.ID)
	fmt.Printf("Name: %s\n", created.Name)
	fmt.Printf("External ID: %s\n", created.ExtID)
	if created.Description != "" {
		fmt.Printf("Description: %s\n", created.Description)
	}
	fmt.Printf("Rate Limit: %d requests per %s\n", created.RateLimit, created.RateWindow)
	fmt.Printf("Created: %s\n", created.CreatedAt)
}

func handleListTeams(ctx *commandContext) {
	session, err := ensureSession()
	if err != nil {
		handleSessionError(err)
		return
	}

	v := buildConfigViper()
	controlBase := strings.TrimSpace(v.GetString("control-base"))
	if controlBase == "" {
		fmt.Println("Control plane base URL is not configured. Set MAAS_CONTROL_BASE or --control-base.")
		return
	}

	client := newAPIClient(v.GetBool("insecure"))
	if err := ensureProfile(client, controlBase, session.AccessToken); err != nil {
		fmt.Fprintf(os.Stderr, "failed to bootstrap profile: %v\n", err)
		return
	}

	// Fetch teams
	listReq, err := http.NewRequest(http.MethodGet, strings.TrimRight(controlBase, "/")+"/teams", nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to build request: %v\n", err)
		return
	}
	listReq.Header.Set("Authorization", "Bearer "+session.AccessToken)

	if ctx.showCurl {
		printCurlCommand(listReq)
		return
	}

	resp, err := client.Do(listReq)
	if err != nil {
		fmt.Fprintf(os.Stderr, "request failed: %v\n", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 300 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		msg := strings.TrimSpace(string(b))
		if msg == "" {
			msg = resp.Status
		}
		fmt.Fprintf(os.Stderr, "list-teams failed: %s\n", msg)
		return
	}

	var payload struct {
		Teams []struct {
			ID          string `json:"id"`
			ExtID       string `json:"ext_id"`
			Name        string `json:"name"`
			Description string `json:"description"`
			RateLimit   int    `json:"rate_limit"`
			RateWindow  string `json:"rate_window"`
			CreatedAt   string `json:"created_at"`
			UpdatedAt   string `json:"updated_at"`
		} `json:"teams"`
		TotalTeams int `json:"total_teams"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		fmt.Fprintf(os.Stderr, "failed to decode response: %v\n", err)
		return
	}

	if len(payload.Teams) == 0 {
		fmt.Println("No teams found. Use /create-team to create one.")
		return
	}

	sort.Slice(payload.Teams, func(i, j int) bool {
		return payload.Teams[i].CreatedAt > payload.Teams[j].CreatedAt
	})

	tw := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "NAME\tEXT_ID\tDESCRIPTION\tLIMIT\tWINDOW\tCREATED\tID")

	for _, team := range payload.Teams {
		description := sanitizeDescription(team.Description)
		if description == "" {
			description = "—"
		}

		created := "—"
		if strings.TrimSpace(team.CreatedAt) != "" {
			if ts, err := time.Parse(time.RFC3339, team.CreatedAt); err == nil {
				created = ts.UTC().Format("2006-01-02 15:04 UTC")
			} else {
				created = team.CreatedAt
			}
		}

		fmt.Fprintf(tw, "%s\t%s\t%s\t%d\t%s\t%s\t%s\n",
			sanitizeDescription(team.Name),
			sanitizeDescription(team.ExtID),
			description,
			team.RateLimit,
			team.RateWindow,
			created,
			team.ID,
		)
	}
	_ = tw.Flush()
}

func handleListKeys(ctx *commandContext) {
	session, err := ensureSession()
	if err != nil {
		handleSessionError(err)
		return
	}

	v := buildConfigViper()
	controlBase := strings.TrimSpace(v.GetString("control-base"))
	if controlBase == "" {
		fmt.Println("Control plane base URL is not configured. Set MAAS_CONTROL_BASE or --control-base.")
		return
	}

	client := newAPIClient(v.GetBool("insecure"))
	if err := ensureProfile(client, controlBase, session.AccessToken); err != nil {
		fmt.Fprintf(os.Stderr, "failed to bootstrap profile: %v\n", err)
		return
	}
	listReq, err := http.NewRequest(http.MethodGet, strings.TrimRight(controlBase, "/")+"/users/me/keys", nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to build request: %v\n", err)
		return
	}
	listReq.Header.Set("Authorization", "Bearer "+session.AccessToken)

	if ctx.showCurl {
		printCurlCommand(listReq)
		return
	}

	resp, err := client.Do(listReq)
	if err != nil {
		fmt.Fprintf(os.Stderr, "request failed: %v\n", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 300 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		msg := strings.TrimSpace(string(b))
		if msg == "" {
			msg = resp.Status
		}
		fmt.Fprintf(os.Stderr, "list-keys failed: %s\n", msg)
		return
	}

	var payload struct {
		Keys []struct {
			ID        string `json:"id"`
			Alias     string `json:"alias"`
			TeamID    string `json:"team_id"`
			TeamExtID string `json:"team_ext_id"`
			TeamName  string `json:"team_name"`
			UserID    string `json:"user_id"`
			UserEmail string `json:"user_email"`
			KeyPrefix string `json:"key_prefix"`
			Key       string `json:"key"`
			CreatedAt string `json:"created_at"`
		} `json:"keys"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		fmt.Fprintf(os.Stderr, "failed to decode response: %v\n", err)
		return
	}

	if len(payload.Keys) == 0 {
		fmt.Println("No API keys found. Use /create-key to generate one.")
		return
	}

	sort.Slice(payload.Keys, func(i, j int) bool {
		return payload.Keys[i].CreatedAt > payload.Keys[j].CreatedAt
	})

	tw := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "NAME\tTEAM\tOWNER\tCREATED\tKEY\tID")
	for _, key := range payload.Keys {
		teamDisplay := sanitizeDescription(key.TeamName)
		if teamDisplay == "" {
			teamDisplay = sanitizeDescription(key.TeamExtID)
		}
		if teamDisplay == "" {
			teamDisplay = sanitizeDescription(key.TeamID)
		}
		created := "—"
		if strings.TrimSpace(key.CreatedAt) != "" {
			if ts, err := time.Parse(time.RFC3339, key.CreatedAt); err == nil {
				created = ts.UTC().Format("2006-01-02 15:04 UTC")
			} else {
				created = key.CreatedAt
			}
		}
		keyValue := strings.TrimSpace(key.Key)
		if keyValue == "" {
			keyValue = "—"
		}
		owner := "—"
		if key.UserEmail != "" {
			owner = sanitizeDescription(key.UserEmail)
		} else if key.UserID != "" {
			owner = sanitizeDescription(key.UserID)
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\n",
			sanitizeDescription(key.Alias),
			teamDisplay,
			owner,
			created,
			keyValue,
			key.ID,
		)
	}
	_ = tw.Flush()
}

func handleUsage(ctx *commandContext) {
	session, err := ensureSession()
	if err != nil {
		handleSessionError(err)
		return
	}

	v := buildConfigViper()
	controlBase := strings.TrimSpace(v.GetString("control-base"))
	if controlBase == "" {
		fmt.Println("Control plane base URL is not configured. Set MAAS_CONTROL_BASE or --control-base.")
		return
	}

	fields := strings.Fields(ctx.args)
	namespace := ""
	if len(fields) > 0 {
		namespace = fields[0]
	} else {
		namespace = strings.TrimSpace(v.GetString("usage-namespace"))
	}
	if namespace == "" {
		fmt.Println("Usage namespace is required. Run /usage <limitador_namespace> [range] or set MAAS_USAGE_NAMESPACE.")
		return
	}

	rangeParam := ""
	if len(fields) > 1 {
		rangeParam = fields[1]
	} else {
		rangeParam = strings.TrimSpace(v.GetString("usage-range"))
	}
	if rangeParam == "" {
		rangeParam = "24h"
	}
	if !usageRangePattern.MatchString(rangeParam) {
		fmt.Println("Range must be a positive duration such as 1m, 1h, or 24h.")
		return
	}

	client := newAPIClient(v.GetBool("insecure"))
	if err := ensureProfile(client, controlBase, session.AccessToken); err != nil {
		fmt.Fprintf(os.Stderr, "failed to validate session: %v\n", err)
		return
	}

	endpoint := strings.TrimRight(controlBase, "/") + "/usage"
	params := url.Values{}
	params.Set("namespace", namespace)
	if rangeParam != "" {
		params.Set("range", rangeParam)
	}
	req, err := http.NewRequest(http.MethodGet, endpoint+"?"+params.Encode(), nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to build request: %v\n", err)
		return
	}
	req.Header.Set("Authorization", "Bearer "+session.AccessToken)

	if ctx.showCurl {
		printCurlCommand(req)
		return
	}

	resp, err := client.Do(req)
	if err != nil {
		fmt.Fprintf(os.Stderr, "request failed: %v\n", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		msg := strings.TrimSpace(string(body))
		if msg == "" {
			msg = resp.Status
		}
		fmt.Fprintf(os.Stderr, "usage request failed: %s\n", msg)
		return
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to read response: %v\n", err)
		return
	}

	if len(body) == 0 {
		fmt.Println("Usage response was empty.")
		return
	}

	var payload usageSummaryResponse
	if err := json.Unmarshal(body, &payload); err != nil {
		fmt.Fprintf(os.Stderr, "failed to decode response: %v\n", err)
		return
	}

	if payload.Range == "" {
		payload.Range = rangeParam
	}

	printUsageSummary(payload)
}

func handleModels(ctx *commandContext) {
	// Legacy IDP mode only
	session, err := ensureSession()
	if err != nil {
		handleSessionError(err)
		return
	}

	v := buildConfigViper()
	controlBase := strings.TrimSpace(v.GetString("control-base"))
	if controlBase == "" {
		fmt.Println("Control plane base URL is not configured. Set MAAS_CONTROL_BASE or --control-base.")
		return
	}

	client := newAPIClient(v.GetBool("insecure"))
	if err := ensureProfile(client, controlBase, session.AccessToken); err != nil {
		fmt.Fprintf(os.Stderr, "failed to validate session: %v\n", err)
		return
	}

	endpoint := strings.TrimRight(controlBase, "/") + "/models"
	req, err := http.NewRequest(http.MethodGet, endpoint, nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to build request: %v\n", err)
		return
	}
	req.Header.Set("Authorization", "Bearer "+session.AccessToken)

	if ctx.showCurl {
		printCurlCommand(req)
		return
	}

	resp, err := client.Do(req)
	if err != nil {
		fmt.Fprintf(os.Stderr, "request failed: %v\n", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		msg := strings.TrimSpace(string(body))
		if msg == "" {
			msg = resp.Status
		}
		fmt.Fprintf(os.Stderr, "models request failed: %s\n", msg)
		return
	}

	var payload struct {
		Models []struct {
			Name      string `json:"name"`
			Namespace string `json:"namespace"`
			URL       string `json:"url"`
			Ready     bool   `json:"ready"`
		} `json:"models"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		fmt.Fprintf(os.Stderr, "failed to decode response: %v\n", err)
		return
	}

	if len(payload.Models) == 0 {
		fmt.Println("No models are currently registered.")
		return
	}

	sort.Slice(payload.Models, func(i, j int) bool {
		if payload.Models[i].Namespace == payload.Models[j].Namespace {
			return payload.Models[i].Name < payload.Models[j].Name
		}
		return payload.Models[i].Namespace < payload.Models[j].Namespace
	})

	fmt.Printf("Available models (%d)\n\n", len(payload.Models))
	for _, model := range payload.Models {
		status := "not ready"
		if model.Ready {
			status = "ready"
		}
		fmt.Printf("  • %s\n", model.Name)
		fmt.Printf("      Namespace: %s\n", model.Namespace)
		if model.URL != "" {
			fmt.Printf("      URL       : %s\n", model.URL)
		} else {
			fmt.Printf("      URL       : (not assigned)\n")
		}
		fmt.Printf("      Status    : %s\n\n", status)
	}
}

func printCurlCommand(req *http.Request) {
	var command strings.Builder
	command.WriteString("curl")

	// Method
	if req.Method != http.MethodGet {
		command.WriteString(fmt.Sprintf(" -X %s", req.Method))
	}

	// URL
	command.WriteString(fmt.Sprintf(" '%s'", req.URL.String()))

	// Headers
	for key, values := range req.Header {
		for _, value := range values {
			command.WriteString(fmt.Sprintf(" -H '%s: %s'", key, value))
		}
	}

	// Body
	if req.Body != nil {
		bodyBytes, err := io.ReadAll(req.Body)
		if err == nil {
			// Restore the body so it can be read again
			req.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))
			if len(bodyBytes) > 0 {
				command.WriteString(fmt.Sprintf(" -d '%s'", string(bodyBytes)))
			}
		}
	}

	fmt.Println(command.String())
}

func sanitizeDescription(desc string) string {
	desc = strings.ReplaceAll(desc, "\n", " ")
	return strings.TrimSpace(desc)
}

func formatFloat(val float64) string {
	if math.IsNaN(val) {
		return "nan"
	}
	if math.IsInf(val, 0) {
		if val > 0 {
			return "+inf"
		}
		return "-inf"
	}
	rounded := math.Round(val)
	if math.Abs(val-rounded) < 1e-6 {
		return fmt.Sprintf("%.0f", rounded)
	}
	return fmt.Sprintf("%.2f", val)
}

func printUsageSummary(payload usageSummaryResponse) {
	end := payload.GeneratedAt
	if end.IsZero() {
		end = time.Now().UTC()
	}

	fmt.Printf("Usage for %s\n", payload.Namespace)
	fmt.Printf("Timeframe: last %s (ending %s UTC)\n\n", payload.Range, end.Format("2006-01-02 15:04:05"))

	items := []struct {
		Key   string
		Label string
	}{
		{"authorized_calls", "Requests"},
		{"limited_calls", "Rate limited"},
		{"authorized_hits", "Token usage"},
	}

	for _, item := range items {
		metric, ok := payload.Metrics[item.Key]
		if !ok {
			fmt.Printf("  • %-12s %s\n", item.Label+":", "no data")
			continue
		}

		fmt.Printf("  • %-12s %s total\n", item.Label+":", formatFloat(metric.Total))
	}

	fmt.Println()
	fmt.Println("Tip: provide /usage <namespace> <range> (e.g. 5m, 6h, 2d) or set MAAS_USAGE_NAMESPACE for defaults.")
}

func keyFingerprint(keyValue string) string {
	sum := sha256.Sum256([]byte(keyValue))
	return strings.ToUpper(hex.EncodeToString(sum[:])[:12])
}

func keysFilePath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".maas-cli", "keys.json"), nil
}

func loadKeyStore() ([]apiKeyRecord, error) {
	path, err := keysFilePath()
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return []apiKeyRecord{}, nil
		}
		return nil, err
	}
	if len(data) == 0 {
		return []apiKeyRecord{}, nil
	}
	var records []apiKeyRecord
	if err := json.Unmarshal(data, &records); err != nil {
		return nil, err
	}
	return records, nil
}

func saveKeyStore(records []apiKeyRecord) error {
	path, err := keysFilePath()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(records, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o600)
}

func upsertKeyRecord(record apiKeyRecord) error {
	records, err := loadKeyStore()
	if err != nil {
		return err
	}
	replaced := false
	for i := range records {
		if records[i].ID == record.ID {
			records[i] = record
			replaced = true
			break
		}
	}
	if !replaced {
		records = append(records, record)
	}
	return saveKeyStore(records)
}

func restoreTerminalState() {
	if !isTTY() {
		return
	}
	if runtime.GOOS == "windows" {
		return
	}
	cmd := exec.Command("stty", "sane")
	cmd.Stdin = os.Stdin
	_ = cmd.Run()
}

func buildConfigViper() *viper.Viper {
	v := viper.New()
	v.SetEnvPrefix("MAAS")
	v.SetEnvKeyReplacer(strings.NewReplacer("-", "_"))
	v.AutomaticEnv()

	v.SetConfigName("config")
	v.SetConfigType("yaml")
	if home, err := os.UserHomeDir(); err == nil {
		v.AddConfigPath(home + "/.maas-cli")
	}
	_ = v.ReadInConfig()

	// Mode selection defaults
	v.SetDefault("idp", false)
	v.SetDefault("show-curl", false)

	// Legacy IDP defaults (only used when --idp is set)
	v.SetDefault("issuer-url", defaultIssuer)
	v.SetDefault("hostname", "")
	v.SetDefault("realm", "maas")
	v.SetDefault("client-id", "maas-client")
	v.SetDefault("client-secret", "maas-client-secret")
	v.SetDefault("no-browser", false)
	v.SetDefault("web", true)
	v.SetDefault("clipboard", false)
	v.SetDefault("with-token", false)
	v.SetDefault("token-file", "")
	v.SetDefault("timeout", 10*time.Minute)
	v.SetDefault("skip-prompt", false)
	v.SetDefault("control-base", defaultControlBase)
	v.SetDefault("data-base", defaultDataBase)
	v.SetDefault("usage-namespace", "")
	v.SetDefault("usage-range", "24h")

	// Base mode API defaults
	v.SetDefault("maas-api-base", defaultMaasAPIBase)
	v.SetDefault("insecure", true)

	return v
}

func runLogin(v *viper.Viper) error {
	issuer := strings.TrimRight(v.GetString("issuer-url"), "/")
	hostname := strings.TrimSpace(v.GetString("hostname"))
	realm := strings.TrimSpace(v.GetString("realm"))
	clientID := v.GetString("client-id")
	clientSecret := v.GetString("client-secret")
	insecure := v.GetBool("insecure")
	noBrowser := v.GetBool("no-browser")
	web := v.GetBool("web")
	clipboard := v.GetBool("clipboard")
	withToken := v.GetBool("with-token")
	tokenFile := v.GetString("token-file")
	timeout := v.GetDuration("timeout")

	// Interactive selection if no explicit host/issuer and running in a TTY (unless disabled)
	skipPrompt := v.GetBool("skip-prompt")
	if hostname == "" && issuer == defaultIssuer && !withToken && isTTY() && !skipPrompt {
		choice, err := promptMaaSChoice()
		if err == nil {
			switch choice {
			case 1: // MaaS Auth (default issuer)
				// keep defaults
			case 2: // Enter Alternative MaaS Keycloak URL
				if u, err := promptCustomIssuer(issuer); err == nil && u != "" {
					issuer = strings.TrimRight(u, "/")
				}
			}
		}
	}

	if hostname != "" {
		if realm == "" {
			realm = "maas"
		}
		issuer = fmt.Sprintf("https://%s/realms/%s", hostname, realm)
	}

	if withToken {
		// Read token from file or stdin and summarize identity
		token, err := readTokenFromInput(tokenFile)
		if err != nil {
			return err
		}
		username, email := extractIdentityFromJWT(token)
		fmt.Println("MaaS CLI - Token Import")
		fmt.Println("────────────────────────")
		if username != "" {
			fmt.Printf("✓ Token for %s", username)
			if email != "" {
				fmt.Printf(" (%s)", email)
			}
			fmt.Println()
		} else {
			fmt.Printf("✓ Token loaded (%d chars)\n", len(token))
		}
		now := time.Now().UTC()
		expiresAt := extractExpiryFromJWT(token)
		session := &sessionData{
			AccessToken: token,
			TokenType:   "bearer",
			ExpiresAt:   expiresAt,
			ObtainedAt:  now,
		}
		if err := saveSession(session); err != nil {
			fmt.Fprintf(os.Stderr, "warning: failed to cache token: %v\n", err)
		} else {
			fmt.Println("Token cached for subsequent commands.")
		}
		return nil
	}

	deviceEndpoint := issuer + "/protocol/openid-connect/auth/device"
	tokenEndpoint := issuer + "/protocol/openid-connect/token"

	httpClient := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: insecure}}}

	fmt.Println("MaaS CLI - Device Login")
	fmt.Println("────────────────────────")
	fmt.Printf("Issuer: %s\n\n", issuer)
	devResp, err := startDeviceFlow(httpClient, deviceEndpoint, clientID, clientSecret)
	if err != nil {
		return fmt.Errorf("start device flow: %w", err)
	}

	fmt.Printf("Login URL: %s\n", devResp.VerificationURIComplete)
	if devResp.UserCode != "" {
		fmt.Printf("One-time code: %s\n", devResp.UserCode)
		if clipboard {
			if err := copyToClipboard(devResp.UserCode); err == nil {
				fmt.Println("(✓ Code copied to clipboard)")
			} else {
				fmt.Printf("(Clipboard unavailable: %v)\n", err)
			}
		}
	}
	fmt.Println("Follow the URL to authenticate with Keycloak, then return here.")
	fmt.Println()

	// Try to open browser unless disabled
	if !noBrowser && web {
		_ = openBrowser(devResp.VerificationURIComplete)
	}

	// 2) Poll for token
	// Ctrl+C cancels the login polling gracefully
	sigCtx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	ctx, cancel := context.WithTimeout(sigCtx, timeout)
	defer cancel()

	fmt.Println("Waiting for Keycloak to confirm the login…")
	token, tr, err := pollForToken(ctx, httpClient, tokenEndpoint, clientID, clientSecret, devResp)
	if err != nil {
		if errors.Is(err, context.Canceled) {
			fmt.Println("\nCancelled.")
			return nil
		}
		return fmt.Errorf("poll for token: %w", err)
	}

	// Show a friendly summary
	username, email := extractIdentityFromJWT(token)
	if username != "" {
		fmt.Printf("\n✓ Logged in as %s", username)
		if email != "" {
			fmt.Printf(" (%s)", email)
		}
		fmt.Println()
	} else {
		fmt.Println("\n✓ Login successful")
	}

	fmt.Println()
	fmt.Println("Access token acquired")

	now := time.Now().UTC()
	expiresAt := time.Time{}
	if tr != nil && tr.ExpiresIn > 0 {
		expiresAt = now.Add(time.Duration(tr.ExpiresIn) * time.Second)
	} else {
		expiresAt = extractExpiryFromJWT(token)
	}
	refreshToken := ""
	tokenType := "bearer"
	if tr != nil {
		refreshToken = strings.TrimSpace(tr.RefreshToken)
		if strings.TrimSpace(tr.TokenType) != "" {
			tokenType = tr.TokenType
		}
	}
	session := &sessionData{
		AccessToken:  token,
		RefreshToken: refreshToken,
		TokenType:    tokenType,
		ExpiresAt:    expiresAt,
		ObtainedAt:   now,
	}
	if err := saveSession(session); err != nil {
		fmt.Fprintf(os.Stderr, "warning: failed to cache session: %v\n", err)
	} else {
		fmt.Println("Session cached for CLI commands.")
	}

	return nil
}

func startDeviceFlow(httpClient *http.Client, endpoint, clientID, clientSecret string) (*DeviceResponse, error) {
	form := url.Values{}
	form.Set("client_id", clientID)
	form.Set("client_secret", clientSecret)

	req, err := http.NewRequest(http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("device endpoint returned %s", resp.Status)
	}
	var dr DeviceResponse
	if err := json.NewDecoder(resp.Body).Decode(&dr); err != nil {
		return nil, err
	}
	if dr.DeviceCode == "" || dr.VerificationURIComplete == "" {
		return nil, errors.New("invalid device response")
	}
	if dr.Interval <= 0 {
		dr.Interval = 5
	}
	return &dr, nil
}

func pollForToken(ctx context.Context, httpClient *http.Client, endpoint, clientID, clientSecret string, dev *DeviceResponse) (string, *TokenResponse, error) {
	start := time.Now()
	interval := time.Duration(dev.Interval) * time.Second
	if interval <= 0 {
		interval = 5 * time.Second
	}

	for {
		select {
		case <-ctx.Done():
			return "", nil, ctx.Err()
		default:
		}

		tr, err := requestToken(httpClient, endpoint, clientID, clientSecret, dev.DeviceCode)
		if err != nil {
			return "", nil, err
		}

		if tr.AccessToken != "" {
			return tr.AccessToken, tr, nil
		}

		switch tr.Error {
		case "authorization_pending":
			// keep waiting
		case "slow_down":
			interval += 1 * time.Second
		case "expired_token":
			return "", nil, errors.New("device code expired; restart login")
		case "access_denied":
			return "", nil, errors.New("access denied by user")
		default:
			if tr.Error != "" {
				return "", nil, fmt.Errorf("token error: %s: %s", tr.Error, tr.ErrorDescription)
			}
		}

		if dev.ExpiresIn > 0 && time.Since(start) > time.Duration(dev.ExpiresIn)*time.Second {
			return "", nil, errors.New("timed out waiting for authorization")
		}
		time.Sleep(interval)
	}
}

func requestToken(httpClient *http.Client, endpoint, clientID, clientSecret, deviceCode string) (*TokenResponse, error) {
	form := url.Values{}
	form.Set("grant_type", "urn:ietf:params:oauth:grant-type:device_code")
	form.Set("device_code", deviceCode)
	form.Set("client_id", clientID)
	form.Set("client_secret", clientSecret)

	req, err := http.NewRequest(http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var tr TokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tr); err != nil {
		return nil, err
	}
	return &tr, nil
}

func openBrowser(url string) error {
	// Best-effort open; ignore errors silently
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		cmd = exec.Command("open", url)
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", url)
	default:
		cmd = exec.Command("xdg-open", url)
	}
	cmd.Stdout = nil
	cmd.Stderr = nil
	return cmd.Start()
}

func extractIdentityFromJWT(token string) (username, email string) {
	parts := strings.Split(token, ".")
	if len(parts) < 2 {
		return "", ""
	}
	payload := parts[1]
	// pad base64 if necessary
	if m := len(payload) % 4; m != 0 {
		payload += strings.Repeat("=", 4-m)
	}
	data, err := base64.URLEncoding.DecodeString(payload)
	if err != nil {
		return "", ""
	}
	var claims map[string]any
	if err := json.Unmarshal(data, &claims); err != nil {
		return "", ""
	}
	if v, ok := claims["preferred_username"].(string); ok {
		username = v
	}
	if v, ok := claims["email"].(string); ok {
		email = v
	}
	return
}

func extractExpiryFromJWT(token string) time.Time {
	parts := strings.Split(token, ".")
	if len(parts) < 2 {
		return time.Time{}
	}
	payload := parts[1]
	if m := len(payload) % 4; m != 0 {
		payload += strings.Repeat("=", 4-m)
	}
	data, err := base64.URLEncoding.DecodeString(payload)
	if err != nil {
		return time.Time{}
	}
	var claims map[string]any
	if err := json.Unmarshal(data, &claims); err != nil {
		return time.Time{}
	}
	switch v := claims["exp"].(type) {
	case float64:
		if v <= 0 {
			return time.Time{}
		}
		return time.Unix(int64(v), 0)
	case json.Number:
		if secs, err := v.Int64(); err == nil {
			return time.Unix(secs, 0)
		}
	case string:
		if secs, err := strconv.ParseInt(v, 10, 64); err == nil {
			return time.Unix(secs, 0)
		}
	}
	return time.Time{}
}

func readTokenFromInput(path string) (string, error) {
	var data []byte
	var err error
	if strings.TrimSpace(path) != "" {
		data, err = os.ReadFile(path)
		if err != nil {
			return "", fmt.Errorf("read token file: %w", err)
		}
	} else {
		// Read from stdin
		fi, _ := os.Stdin.Stat()
		if (fi.Mode() & os.ModeCharDevice) != 0 {
			return "", errors.New("--with-token expects token on stdin or use --token-file")
		}
		data, err = ioReadAllLimit(os.Stdin, 2*1024*1024)
		if err != nil {
			return "", fmt.Errorf("read stdin: %w", err)
		}
	}
	token := strings.TrimSpace(string(data))
	if token == "" {
		return "", errors.New("empty token input")
	}
	return token, nil
}

func ioReadAllLimit(r *os.File, max int64) ([]byte, error) {
	// Minimal readAll with size cap
	var b strings.Builder
	buf := make([]byte, 4096)
	var n int
	var total int64
	for {
		nn, err := r.Read(buf)
		if nn > 0 {
			n += nn
			total += int64(nn)
			if total > max {
				return nil, errors.New("input too large")
			}
			b.Write(buf[:nn])
		}
		if err != nil {
			if errors.Is(err, os.ErrClosed) {
				break
			}
			if err.Error() == "EOF" {
				break
			}
			if err != nil {
				return []byte(b.String()), nil
			}
		}
		if nn == 0 {
			break
		}
	}
	return []byte(b.String()), nil
}

func copyToClipboard(text string) error {
	// Try common OS clipboard tools
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		cmd = exec.Command("pbcopy")
	case "windows":
		cmd = exec.Command("clip")
	default:
		// Try Wayland, then X11 utilities
		if _, err := exec.LookPath("wl-copy"); err == nil {
			cmd = exec.Command("wl-copy")
		} else if _, err := exec.LookPath("xclip"); err == nil {
			cmd = exec.Command("xclip", "-selection", "clipboard")
		} else if _, err := exec.LookPath("xsel"); err == nil {
			cmd = exec.Command("xsel", "--clipboard", "--input")
		} else {
			return errors.New("no clipboard utility found (install wl-copy/xclip/xsel)")
		}
	}
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return err
	}
	if err := cmd.Start(); err != nil {
		return err
	}
	_, _ = stdin.Write([]byte(text))
	_ = stdin.Close()
	return cmd.Wait()
}

func isTTY() bool {
	fi, err := os.Stdin.Stat()
	if err != nil {
		return false
	}
	return (fi.Mode() & os.ModeCharDevice) != 0
}

func promptMaaSChoice() (int, error) {
	if !isTTY() {
		// Non-interactive: default to option 1
		return 1, nil
	}
	options := []string{"MaaS Auth", "Enter Alternative MaaS Keycloak URL"}
	var choice string
	prompt := &survey.Select{
		Message:  "? Select login option",
		Options:  options,
		Default:  options[0],
		PageSize: 5,
	}
	if err := survey.AskOne(prompt, &choice); err != nil {
		return 0, err
	}
	for i, opt := range options {
		if opt == choice {
			return i + 1, nil
		}
	}
	return 1, nil
}

func promptCustomIssuer(defaultURL string) (string, error) {
	reader := bufio.NewReader(os.Stdin)
	fmt.Printf("Issuer URL [%s]: ", defaultURL)
	line, err := reader.ReadString('\n')
	if err != nil {
		return "", err
	}
	line = strings.TrimSpace(line)
	if line == "" {
		return defaultURL, nil
	}
	return line, nil
}
